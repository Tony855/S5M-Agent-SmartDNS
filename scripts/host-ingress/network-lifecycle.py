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

def read_config(path: Path) -> dict:
    current = Path("/")
    for part in path.absolute().parts[1:-1]:
        current = current / part
        st_parent = current.lstat()
        if not stat.S_ISDIR(st_parent.st_mode) or st_parent.st_uid != 0 or st_parent.st_mode & 0o022:
            raise LifecycleError(f"config parent {current} must be root-owned, non-writable directory")
    if path.is_symlink(): raise LifecycleError("config must not be a symlink")
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise LifecycleError("config must be a root-owned regular file with mode 0600 or stricter")
    if st.st_size > 8192: raise LifecycleError("config exceeds 8 KiB")
    raw = path.read_bytes()
    try: cfg = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e: raise LifecycleError("config must be valid UTF-8 JSON") from e
    keys = {"version","network","container","interface","ipv4_subnet","ipv4_gateway","ipv4_address","ipv6_subnet","ipv6_gateway","ipv6_address"}
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
        if gw == addr or addr == net.network_address or (family == 4 and addr == net.broadcast_address):
            raise LifecycleError(f"{suffix} address conflicts with gateway/network boundary")
        if family == 4 and net.prefixlen > 30:
            raise LifecycleError("IPv4 Docker bridge subnet must be /30 or larger")
        if family == 6 and net.prefixlen > 120:
            raise LifecycleError("IPv6 Docker bridge subnet must be /120 or larger")
        values[family]=(net,gw,addr)
    if 4 not in values: raise LifecycleError("IPv4 ingress is mandatory")
    if len(values)==2 and values[4][0].overlaps(values[6][0]): raise LifecycleError("overlapping address families")
    cfg["_networks"]=values
    return cfg

def run(args, *, check=True):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if check and p.returncode: raise LifecycleError(f"command failed ({p.returncode}): {' '.join(args)}: {p.stderr.strip()}")
    return p

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

def container_networks(name):
    p=run(["docker","inspect",name])
    try: return json.loads(p.stdout)[0]["NetworkSettings"]["Networks"]
    except Exception as e: raise LifecycleError(f"cannot inspect container networks: {e}") from e

def default_routes(container):
    v4=run(["docker","exec",container,"ip","-4","route","show","default"]).stdout.strip().splitlines()
    v6=run(["docker","exec",container,"ip","-6","route","show","default"],check=False).stdout.strip().splitlines()
    return v4,v6

def provision(cfg):
    help_text=run(["docker","network","connect","--help"],check=False).stdout
    if "--gw-priority" not in help_text:
        raise LifecycleError("Docker CLI must support network connect --gw-priority to preserve default bridge egress")
    net=inspect_network(cfg["network"]); created=False; connected=False
    if net is None:
        create_network(cfg); created=True
        net=inspect_network(cfg["network"])
        if net is None: raise LifecycleError("Docker did not create the requested network")
    validate_existing(net,cfg)
    attached=container_networks(cfg["container"])
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
            if created: run(["docker","network","rm",cfg["network"]],check=False)
            raise
    try:
        attached=container_networks(cfg["container"])
        if "bridge" not in attached or cfg["network"] not in attached: raise LifecycleError("container must retain default bridge plus routed ingress network")
        for family,(_,_,address) in cfg["_networks"].items():
            field="IPAddress" if family==4 else "GlobalIPv6Address"
            if attached[cfg["network"]].get(field)!=str(address): raise LifecycleError(f"container ingress IPv{family} address mismatch")
        routes=default_routes(cfg["container"])
        bridge=attached["bridge"]
        gw4=bridge.get("Gateway")
        if not gw4 or not any(f"via {gw4}" in line for line in routes[0]):
            raise LifecycleError(f"default IPv4 egress changed; expected default bridge gateway {gw4}, got {routes[0]}")
        if 6 in cfg["_networks"]:
            gw6=bridge.get("IPv6Gateway")
            if gw6 and not any(f"via {gw6}" in line for line in routes[1]):
                raise LifecycleError(f"default IPv6 egress changed; expected default bridge gateway {gw6}, got {routes[1]}")
    except Exception:
        if connected: run(["docker","network","disconnect",cfg["network"],cfg["container"]],check=False)
        if created: run(["docker","network","rm",cfg["network"]],check=False)
        raise
    print(f"ROUTED_INGRESS_READY network={cfg['network']} container={cfg['container']} default_bridge_egress=preserved")
    print("External router static routes and physical LAN source-IP acceptance remain separate mandatory steps.")

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
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("action",choices=("provision","uninstall")); p.add_argument("--config",type=Path,default=Path("/etc/s5m-agent-ingress/network.json"))
    a=p.parse_args()
    if os.geteuid()!=0: raise LifecycleError("run on Docker host as root")
    cfg=read_config(a.config)
    if a.action=="provision": provision(cfg)
    else: uninstall(cfg)

if __name__=="__main__":
    try: main()
    except Exception as e:
        print(f"FAIL: {e}",file=sys.stderr); raise SystemExit(1)
