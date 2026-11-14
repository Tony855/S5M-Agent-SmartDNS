package app

import ("testing"; "fmt")

func TestBuildSmartDNSRoutingPlanLegacyIsNonMutating(t *testing.T) {
	got, err := BuildSmartDNSRoutingPlan(SmartDNSRoutingConfig{}, nil)
	if err != nil { t.Fatal(err) }
	if got.Mode != "legacy" || got.GroupName != "" || len(got.Clients) != 0 {
		t.Fatalf("legacy config must not opt existing nodes into new routing: %#v", got)
	}
}

func TestBuildSmartDNSRoutingPlanSharedFallbackIsDynamicAndDeterministic(t *testing.T) {
	cfg := SmartDNSRoutingConfig{Mode: SmartDNSProxyModeShared}
	proxies := []SmartDNSProxyRef{{Name:"node-z", Enabled:true}, {Name:"node-a", Enabled:true}, {Name:"disabled", Enabled:false}}
	got, err := BuildSmartDNSRoutingPlan(cfg, proxies)
	if err != nil { t.Fatal(err) }
	if got.Strategy != SmartDNSDefaultStrategy || got.GroupName != "SMARTDNS-PROXY" { t.Fatalf("unexpected shared plan: %#v", got) }
	if len(got.ProxyNames) != 2 || got.ProxyNames[0] != "node-a" || got.ProxyNames[1] != "node-z" {
		t.Fatalf("enabled proxy references must be sorted and dynamic: %#v", got.ProxyNames)
	}
}

func TestBuildSmartDNSRoutingPlanPerClientBindsEachResolverToItsOwnProxy(t *testing.T) {
	cfg := SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient, Clients:[]SmartDNSClientRoute{
		{ClientCIDR:"192.168.18.33/32", ProxyName:"Mihomo-IPv6-24581", ListenPort:16081},
		{ClientCIDR:"192.168.18.23/32", ProxyName:"Mihomo-IPv6-24580", ListenPort:16080},
	}}
	proxies := []SmartDNSProxyRef{{Name:"Mihomo-IPv6-24580",Enabled:true},{Name:"Mihomo-IPv6-24581",Enabled:true}}
	got, err := BuildSmartDNSRoutingPlan(cfg, proxies)
	if err != nil { t.Fatal(err) }
	if len(got.Clients)!=2 { t.Fatalf("got %d client routes",len(got.Clients)) }
	if got.Clients[0].ClientCIDR!="192.168.18.23/32" || got.Clients[0].ProxyName!="Mihomo-IPv6-24580" {
		t.Fatalf("first client mapping changed: %#v",got.Clients[0])
	}
	if got.Clients[1].ClientCIDR!="192.168.18.33/32" || got.Clients[1].ProxyName!="Mihomo-IPv6-24581" {
		t.Fatalf("second client mapping changed: %#v",got.Clients[1])
	}
}

func TestBuildSmartDNSRoutingPlanRejectsInvalidMappings(t *testing.T) {
	proxies:=[]SmartDNSProxyRef{{Name:"node-a",Enabled:true}}
	cases:=[]struct{name string; cfg SmartDNSRoutingConfig}{
		{"unknown mode",SmartDNSRoutingConfig{Mode:"magic"}},
		{"unsupported strategy",SmartDNSRoutingConfig{Mode:SmartDNSProxyModeShared,Strategy:"load-balance"}},
		{"no proxies",SmartDNSRoutingConfig{Mode:SmartDNSProxyModeShared}},
		{"empty clients",SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient}},
		{"invalid cidr",SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:"not-a-cidr",ProxyName:"node-a"}}}},
		{"unknown proxy",SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.1.2/32",ProxyName:"missing"}}}},
		{"duplicate cidr",SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.1.2/32",ProxyName:"node-a"},{ClientCIDR:"192.168.1.2/32",ProxyName:"node-a"}}}},
		{"overlapping cidr",SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.1.0/24",ProxyName:"node-a"},{ClientCIDR:"192.168.1.2/32",ProxyName:"node-a"}}}},
		{"duplicate port",SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.1.2/32",ProxyName:"node-a",ListenPort:6054},{ClientCIDR:"192.168.1.3/32",ProxyName:"node-a",ListenPort:6054}}}},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			available := proxies
			if tc.name == "no proxies" { available = nil }
			if _,err:=BuildSmartDNSRoutingPlan(tc.cfg,available);err==nil { t.Fatal("expected validation error") }
		})
	}
}

func TestBuildSmartDNSRoutingPlanRejectsDisabledProxy(t *testing.T) {
	cfg:=SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.1.2/32",ProxyName:"node-a"}}}
	if _,err:=BuildSmartDNSRoutingPlan(cfg,[]SmartDNSProxyRef{{Name:"node-a",Enabled:false}});err==nil { t.Fatal("disabled proxy must not be a DNS egress") }
}


func TestBuildSmartDNSRoutingPlanRejectsPrivilegedListenerPorts(t *testing.T) {
	for _, port := range []int{1, 53, 1023} {
		t.Run(fmt.Sprintf("port-%d", port), func(t *testing.T) {
			cfg := SmartDNSRoutingConfig{
				Mode: SmartDNSProxyModePerClient,
				Clients: []SmartDNSClientRoute{{ClientCIDR: "192.168.1.10/32", ProxyName: "node-a", ListenPort: port}},
			}
			if _, err := BuildSmartDNSRoutingPlan(cfg, []SmartDNSProxyRef{{Name: "node-a", Enabled: true}}); err == nil {
				t.Fatalf("privileged port %d must be rejected", port)
			}
		})
	}
}

func TestBuildSmartDNSRoutingPlanAcceptsMinimumUnprivilegedListenerPort(t *testing.T) {
	cfg := SmartDNSRoutingConfig{
		Mode: SmartDNSProxyModePerClient,
		Clients: []SmartDNSClientRoute{{ClientCIDR: "192.168.1.10/32", ProxyName: "node-a", ListenPort: 1024}},
	}
	if _, err := BuildSmartDNSRoutingPlan(cfg, []SmartDNSProxyRef{{Name: "node-a", Enabled: true}}); err != nil {
		t.Fatalf("port 1024 should be accepted: %v", err)
	}
}

func TestBuildSmartDNSRoutingPlanSelectUsesManagedPROXYGroup(t *testing.T) {
	got, err := BuildSmartDNSRoutingPlan(
		SmartDNSRoutingConfig{Mode: SmartDNSProxyModeShared, Strategy: SmartDNSStrategySelect},
		[]SmartDNSProxyRef{{Name: "node-a", Enabled: true}},
	)
	if err != nil { t.Fatal(err) }
	if got.GroupName != "PROXY" || got.Strategy != SmartDNSStrategySelect {
		t.Fatalf("manual strategy must follow the managed PROXY selection group: %#v", got)
	}
}

func TestBuildSmartDNSRoutingPlanFallbackIsDefault(t *testing.T) {
	got, err := BuildSmartDNSRoutingPlan(
		SmartDNSRoutingConfig{Mode: SmartDNSProxyModeShared},
		[]SmartDNSProxyRef{{Name: "node-a", Enabled: true}},
	)
	if err != nil { t.Fatal(err) }
	if got.Strategy != SmartDNSStrategyFallback || got.GroupName != SmartDNSGroupName {
		t.Fatalf("new shared SmartDNS routing must default to ordered fallback: %#v", got)
	}
}


func TestBuildSmartDNSRoutingPlanRejectsReservedCIDRsAndOverlapsAfterMasking(t *testing.T) {
 proxies:=[]SmartDNSProxyRef{{Name:"node-a",Enabled:true}}
 for _,cidr:=range []string{"0.0.0.0/0","::/0","127.0.0.0/8","::1/128","169.254.0.0/16","fe80::/10","224.0.0.0/4","ff00::/8","::ffff:192.0.2.0/120","255.255.255.255/32"} {
  t.Run(cidr,func(t *testing.T){
   cfg:=SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:cidr,ProxyName:"node-a"}}}
   if _,err:=BuildSmartDNSRoutingPlan(cfg,proxies);err==nil {t.Fatalf("unsafe CIDR %q accepted",cidr)}
  })
 }
 cfg:=SmartDNSRoutingConfig{Mode:SmartDNSProxyModePerClient,Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.50.7/24",ProxyName:"node-a"},{ClientCIDR:"192.168.50.8/32",ProxyName:"node-a"}}}
 if _,err:=BuildSmartDNSRoutingPlan(cfg,proxies);err==nil {t.Fatal("overlap after masking accepted")}
}
