#!/usr/bin/env python3
"""Provision the dedicated routed Docker bridge for S5M Agent DNS ingress.

Run only on the Docker host as root. This helper never runs in the Agent
container, never changes host routes, and never publishes DNS ports.
"""
from __future__ import annotations
import argparse, ipaddress, json, os, re, stat, subprocess, sys
from pathlib import Path

OWNER = "com.s5m.managed"
VALUE = "s5m-agent-dns-ingress"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")

class LifecycleError(RuntimeError): pass

def secure_read(path: Path, max_bytes: int, *, require_root: bool = True) -> bytes:
    if require_root:
        current=Path("/")
        for part in path.absolute().parts[1:-1]:
            current=current/part
            parent_st=current.lstat()
            if not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid!=0 or parent_st.st_mode & 0o022:
                raise LifecycleError(f"config parent {current} must be root-owned and non-writable")
    expected_owner=0 if require_root else os.geteuid()
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=expected_owner or st.st_mode & 0o077 or st.st_size>max_bytes:
        raise LifecycleError(f"{path} must be an appropriately owned regular file, mode 0600 or stricter, and <= {max_bytes} bytes")
    flags=os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_CLOEXEC",0)
    fd=os.open(path,flags)
    try:
        opened=os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid!=expected_owner or opened.st_mode & 0o077 or opened.st_size>max_bytes:
            raise LifecycleError(f"{path} changed while opening")
        chunks=[]; total=0
        while True:
            chunk=os.read(fd,min(4096,max_bytes+1-total))
            if not chunk: break
            chunks.append(chunk); total+=len(chunk)
            if total>max_bytes: raise LifecycleError(f"{path} exceeds {max_bytes} bytes")
        return b"".join(chunks)
    finally: os.close(fd)

def read_config(path: Path, *, require_root: bool = True) -> dict:
    raw=secure_read(path,8192,require_root=require_root)
    try: cfg = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e: raise LifecycleError("config must be valid UTF-8 JSON") from e
    keys = {"version","network","container","interface","ipv4_subnet","ipv4_gateway","ipv4_address","ipv6_subnet","ipv6_gateway","ipv6_address","client_cidrs"}
    if not isinstance(cfg,dict) or set(cfg) != keys or type(cfg["version"]) is not int or cfg["version"] != 1:
        raise LifecycleError("invalid config schema/version")
    for key in ("network","container"):
        if not isinstance(cfg[key],str) or not NAME_RE.fullmatch(cfg[key]): raise LifecycleError(f"invalid {key}")
    if not isinstance(cfg["interface"],str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}",cfg["interface"]):
        raise LifecycleError("invalid trusted host interface")
    values={}
    for family in (4,6):
        suffix=f"ipv{family}"
        fields=[cfg[f"{suffix}_{x}"] for x in ("subnet","gateway","address")]
        if family == 4 and any(x is None for x in fields): raise LifecycleError("IPv4 subnet, gateway and address are required")
        if family == 6 and not all(x is None for x in fields) and any(x is None for x in fields): raise LifecycleError("IPv6 fields must be all present or all null")
        if all(x is None for x in fields): continue
        try:
            net=ipaddress.ip_network(fields[0],strict=True); gw=ipaddress.ip_address(fields[1]); addr=ipaddress.ip_address(fields[2])
        except ValueError as e: raise LifecycleError(f"invalid {suffix} network/gateway/address") from e
        if net.version != family or gw.version != family or addr.version != family or gw not in net or addr not in net:
            raise LifecycleError(f"{suffix} family/range mismatch")
        if any(x.is_unspecified or x.is_loopback or x.is_link_local or x.is_multicast for x in (gw,addr)):
            raise LifecycleError(f"{suffix} gateway/address must be routable unicast")
        if gw == addr or gw == net.network_address or addr == net.network_address or (family == 4 and (gw == net.broadcast_address or addr == net.broadcast_address)):
            raise LifecycleError(f"{suffix} gateway/address conflicts with network boundary")
        if family == 4 and net.prefixlen > 30:
            raise LifecycleError("IPv4 Docker bridge subnet must be /30 or larger")
        if family == 6 and net.prefixlen > 120:
            raise LifecycleError("IPv6 Docker bridge subnet must be /120 or larger")
        values[family]=(net,gw,addr)
    if 4 not in values: raise LifecycleError("IPv4 ingress is mandatory")
    if len(values)==2 and values[4][0].overlaps(values[6][0]): raise LifecycleError("overlapping address families")
    cidr_values=cfg["client_cidrs"]
    if not isinstance(cidr_values,list) or not cidr_values or len(cidr_values)>128:
        raise LifecycleError("client_cidrs must contain 1..128 entries")
    client_networks=[]
    for value in cidr_values:
        if not isinstance(value,str): raise LifecycleError("each client CIDR must be a string")
        try: net=ipaddress.ip_network(value,strict=True)
        except ValueError as e: raise LifecycleError(f"invalid or non-canonical client CIDR: {value}") from e
        if net.prefixlen==0 or net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified or net.is_reserved or getattr(net.network_address,"ipv4_mapped",None):
            raise LifecycleError(f"client CIDR is not an allowed unicast network: {value}")
        client_networks.append(net)
    if len(set(client_networks))!=len(client_networks): raise LifecycleError("duplicate client CIDR")
    for i,left in enumerate(client_networks):
        for right in client_networks[i+1:]:
            if left.version==right.version and left.overlaps(right): raise LifecycleError("overlapping client CIDRs")
    if {n.version for n in client_networks}!=set(values):
        raise LifecycleError("client CIDR families must exactly match configured ingress address families")
    for client_net in client_networks:
        for ingress_net,_,_ in values.values():
            if client_net.version==ingress_net.version and client_net.overlaps(ingress_net):
                raise LifecycleError("client CIDRs must not overlap the routed Docker ingress subnet")
    cfg["_networks"]=values
    cfg["_client_networks"]=client_networks
    return cfg

def run(args, *, check=True):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if check and p.returncode: raise LifecycleError(f"command failed ({p.returncode}): {' '.join(args)}: {p.stderr.strip()}")
    return p

def validate_firewall_contract(cfg: dict, path: Path, *, require_root: bool = True) -> None:
    raw=secure_read(path,16384,require_root=require_root)
    try: fw=json.loads(raw)
    except (UnicodeDecodeError,json.JSONDecodeError) as e: raise LifecycleError("firewall config must be valid UTF-8 JSON") from e
    required={"version","interface","ipv4_address","ipv6_address","client_cidrs"}
    if not isinstance(fw,dict) or set(fw)!=required or type(fw["version"]) is not int or fw["version"]!=1:
        raise LifecycleError("firewall config schema/version mismatch")
    expected4=str(cfg["_networks"][4][2])
    expected6=str(cfg["_networks"][6][2]) if 6 in cfg["_networks"] else None
    cidrs=sorted(str(net) for net in cfg["_client_networks"])
    if fw["interface"]!=cfg["interface"] or fw["ipv4_address"]!=expected4 or fw["ipv6_address"]!=expected6:
        raise LifecycleError("firewall config interface/ingress addresses do not match routed Docker network config")
    if not isinstance(fw["client_cidrs"],list) or sorted(fw["client_cidrs"])!=cidrs:
        raise LifecycleError("firewall config client CIDRs do not exactly match routed Docker network config")

def inspect_network(name):
    p=run(["docker","network","inspect",name],check=False)
    if p.returncode: return None
    try: data=json.loads(p.stdout)[0]
    except Exception as e: raise LifecycleError(f"cannot parse Docker network inspect: {e}") from e
    return data

def labels(network):
    return network.get("Labels") or {}

def expected_subnets(cfg):
    return {f: (str(v[0]),str(v[1])) for f,v in cfg["_networks"].items()}

def validate_existing(net,cfg):
    if labels(net).get(OWNER)!=VALUE: raise LifecycleError("network name already exists but is not owned by S5M ingress lifecycle")
    if net.get("Driver")!="bridge": raise LifecycleError("managed network driver drift")
    ipam=net.get("IPAM",{}).get("Config",[])
    actual={}
    for item in ipam:
        try:
            n=ipaddress.ip_network(item.get("Subnet",""),strict=True)
            actual[n.version]=(str(n),str(ipaddress.ip_address(item.get("Gateway",""))))
        except ValueError: raise LifecycleError("managed network has malformed IPAM config")
    if actual!=expected_subnets(cfg): raise LifecycleError("managed network subnet/gateway drift; refusing destructive repair")
    opts=net.get("Options") or {}
    required={"com.docker.network.bridge.gateway_mode_ipv4":"routed",
              "com.docker.network.bridge.trusted_host_interfaces":cfg["interface"]}
    if 6 in cfg["_networks"]: required["com.docker.network.bridge.gateway_mode_ipv6"]="routed"
    for k,v in required.items():
        if opts.get(k)!=v: raise LifecycleError(f"managed network option drift: {k}")
    return net

def create_network(cfg):
    args=["docker","network","create","--driver","bridge","--label",f"{OWNER}={VALUE}",
          "--opt","com.docker.network.bridge.gateway_mode_ipv4=routed",
          "--opt",f"com.docker.network.bridge.trusted_host_interfaces={cfg['interface']}"]
    if 6 in cfg["_networks"]: args += ["--ipv6","--opt","com.docker.network.bridge.gateway_mode_ipv6=routed"]
    for f,(net,gw,addr) in cfg["_networks"].items():
        args += ["--subnet",str(net),"--gateway",str(gw)]
    args += [cfg["network"]]
    run(args)

def host_next_hops(cfg):
    result=run(["ip","-j","addr","show","dev",cfg["interface"]])
    try: devices=json.loads(result.stdout)
    except json.JSONDecodeError as e: raise LifecycleError("cannot parse host interface addresses") from e
    candidates={4:[],6:[]}
    for device in devices:
        for item in device.get("addr_info",[]):
            if item.get("scope")!="global": continue
            try: address=ipaddress.ip_address(item.get("local",""))
            except ValueError: continue
            if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast:
                continue
            candidates[address.version].append(str(address))
    next_hops={}
    for family in cfg["_networks"]:
        if not candidates[family]:
            raise LifecycleError(f"trusted ingress interface {cfg['interface']} has no global IPv{family} address for the upstream router static route")
        next_hops[family]=candidates[family][0]
    return next_hops

def inspect_container(name):
    p=run(["docker","inspect",name])
    try: return json.loads(p.stdout)[0]
    except Exception as e: raise LifecycleError(f"cannot inspect container: {e}") from e

def validate_dns_port_bindings(container: dict, cfg: dict) -> None:
    networks=container.get("NetworkSettings",{}).get("Networks") or {}
    routed_attached=cfg["network"] in networks
    ports=container.get("NetworkSettings",{}).get("Ports") or {}
    for proto in ("udp","tcp"):
        entries=ports.get(f"6055/{proto}") or []
        ipv4_loopback=[x for x in entries if x.get("HostIp")=="127.0.0.1" and str(x.get("HostPort","")).isdigit() and 1<=int(x["HostPort"])<=65535]
        if len(ipv4_loopback)!=1:
            raise LifecycleError(f"DNS 6055/{proto} must have exactly one IPv4 host mapping bound to 127.0.0.1 with an allocated ephemeral port; found {entries!r}")
        routed_v4=[x for x in entries if x.get("HostIp")=="0.0.0.0" and x.get("HostPort","") in ("",None)]
        routed_v6=[x for x in entries if x.get("HostIp")=="::" and x.get("HostPort","") in ("",None)]
        allowed=[*ipv4_loopback]
        if routed_attached:
            if len(routed_v4)!=1:
                raise LifecycleError(f"routed IPv4 DNS 6055/{proto} mapping must have an empty host port; found {entries!r}")
            allowed.extend(routed_v4)
        if 6 in cfg["_networks"]:
            if len(routed_v6)!=1:
                raise LifecycleError(f"routed IPv6 DNS 6055/{proto} mapping must have an empty host port; refuse public IPv6 exposure")
            allowed.extend(routed_v6)
        if len(entries)!=len(allowed):
            raise LifecycleError(f"DNS 6055/{proto} contains an unexpected or public host binding: {entries!r}")

def container_networks(name):
    return inspect_container(name)["NetworkSettings"]["Networks"]

def default_routes(container):
    v4=run(["docker","exec",container,"ip","-4","route","show","default"]).stdout.strip().splitlines()
    v6=run(["docker","exec",container,"ip","-6","route","show","default"],check=False).stdout.strip().splitlines()
    return v4,v6

def preserves_single_default_route(routes, gateway):
    entries=[line.strip() for line in routes if line.strip()]
    return len(entries)==1 and f"via {gateway}" in entries[0]

def provision(cfg):
    if run(["ip","link","show","dev",cfg["interface"]],check=False).returncode:
        raise LifecycleError(f"trusted ingress interface does not exist: {cfg['interface']}")
    next_hops=host_next_hops(cfg)
    help_result=run(["docker","network","connect","--help"],check=False)
    help_text=help_result.stdout + help_result.stderr
    if "--gw-priority" not in help_text:
        raise LifecycleError("Docker CLI must support network connect --gw-priority to preserve default bridge egress")
    net=inspect_network(cfg["network"]); created=False; connected=False
    if net is None:
        create_network(cfg); created=True
        net=inspect_network(cfg["network"])
        if net is None:
            run(["docker","network","rm",cfg["network"]],check=False)
            raise LifecycleError("Docker did not create the requested network")
    try:
        validate_existing(net,cfg)
        container=inspect_container(cfg["container"])
        validate_dns_port_bindings(container,cfg)
        attached=container["NetworkSettings"]["Networks"]
    except Exception:
        if created: run(["docker","network","rm",cfg["network"]],check=False)
        raise
    if cfg["network"] in attached:
        actual=attached[cfg["network"]]
        for family,(_,_,address) in cfg["_networks"].items():
            field="IPAddress" if family==4 else "GlobalIPv6Address"
            if actual.get(field)!=str(address): raise LifecycleError("container already attached with a different ingress address")
    else:
        args=["docker","network","connect","--gw-priority","-1","--ip",str(cfg["_networks"][4][2])]
        if 6 in cfg["_networks"]: args += ["--ip6",str(cfg["_networks"][6][2])]
        args += [cfg["network"],cfg["container"]]
        try:
            run(args); connected=True
        except Exception:
            # Docker CLI can report an error after the daemon has completed an
            # endpoint attach. Inspect before cleanup so a newly-created network
            # is never left behind with an unexpected live endpoint.
            try:
                if cfg["network"] in container_networks(cfg["container"]):
                    run(["docker","network","disconnect",cfg["network"],cfg["container"]],check=False)
            except Exception:
                pass
            if created: run(["docker","network","rm",cfg["network"]],check=False)
            raise
    try:
        verified_container=inspect_container(cfg["container"])
        validate_dns_port_bindings(verified_container,cfg)
        attached=verified_container["NetworkSettings"]["Networks"]
        if "bridge" not in attached or cfg["network"] not in attached: raise LifecycleError("container must retain default bridge plus routed ingress network")
        for family,(_,_,address) in cfg["_networks"].items():
            field="IPAddress" if family==4 else "GlobalIPv6Address"
            if attached[cfg["network"]].get(field)!=str(address): raise LifecycleError(f"container ingress IPv{family} address mismatch")
        routes=default_routes(cfg["container"])
        bridge=attached["bridge"]
        gw4=bridge.get("Gateway")
        if not gw4 or not preserves_single_default_route(routes[0],gw4):
            raise LifecycleError(f"default IPv4 egress changed; expected exactly one default route via bridge gateway {gw4}, got {routes[0]}")
        if 6 in cfg["_networks"]:
            gw6=bridge.get("IPv6Gateway")
            if not gw6:
                raise LifecycleError("dual-stack ingress requires an IPv6 gateway on the default bridge to preserve default IPv6 egress")
            if not preserves_single_default_route(routes[1],gw6):
                raise LifecycleError(f"default IPv6 egress changed; expected exactly one default route via bridge gateway {gw6}, got {routes[1]}")
    except Exception:
        if connected: run(["docker","network","disconnect",cfg["network"],cfg["container"]],check=False)
        if created: run(["docker","network","rm",cfg["network"]],check=False)
        raise
    print(f"ROUTED_INGRESS_READY network={cfg['network']} container={cfg['container']} default_bridge_egress=preserved")
    for family,(subnet,_,_) in cfg["_networks"].items():
        print(f"UPSTREAM_ROUTER_STATIC_ROUTE IPv{family}: route {subnet} via {next_hops[family]} on {cfg['interface']}")
    print("Apply the displayed static routes on the upstream router; this helper does not change router or host routes.")
    print("Physical LAN source-IP acceptance remains a separate mandatory step.")

def uninstall(cfg):
    net=inspect_network(cfg["network"])
    if net is None:
        print("network already absent"); return
    validate_existing(net,cfg)
    attached=net.get("Containers") or {}
    if attached:
        ids={v.get("Name") for v in attached.values()}
        if ids!={cfg["container"]}: raise LifecycleError(f"refusing removal: network has other attached containers: {sorted(str(x) for x in ids)}")
        run(["docker","network","disconnect",cfg["network"],cfg["container"]])
    run(["docker","network","rm",cfg["network"]])
    print(f"REMOVED managed ingress network {cfg['network']}")

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("action",choices=("provision","uninstall")); p.add_argument("--config",type=Path,default=Path("/etc/s5m-agent-ingress/network.json")); p.add_argument("--firewall-config",type=Path,default=Path("/etc/s5m-agent-ingress/config.json"))
    a=p.parse_args()
    if os.geteuid()!=0: raise LifecycleError("run on Docker host as root")
    cfg=read_config(a.config)
    if a.action=="provision":
        validate_firewall_contract(cfg,a.firewall_config)
        provision(cfg)
    else:
        # Cleanup must remain possible after firewall settings change; network
        # ownership and exact Docker network shape are still independently checked.
        uninstall(cfg)

if __name__=="__main__":
    try: main()
    except Exception as e:
        print(f"FAIL: {e}",file=sys.stderr); raise SystemExit(1)
