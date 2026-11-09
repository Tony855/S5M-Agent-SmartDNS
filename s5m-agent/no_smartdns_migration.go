package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var agentSupportsSmartDNS = "true"

func smartDNSFeatureSupported() bool { return agentSupportsSmartDNS != "false" }

func normalizeNoSmartDNSYAML(data []byte) ([]byte, error) {
	if smartDNSFeatureSupported() { return data, nil }
	tmp, err := os.CreateTemp("", "s5m-no-smartdns-config-*.yaml")
	if err != nil { return nil, err }
	path := tmp.Name()
	if err := tmp.Chmod(0600); err != nil { tmp.Close(); os.Remove(path); return nil, err }
	if _, err := tmp.Write(data); err != nil { tmp.Close(); os.Remove(path); return nil, err }
	if err := tmp.Close(); err != nil { os.Remove(path); return nil, err }
	defer os.Remove(path)
	defer os.Remove(path + ".pre-no-smartdns")
	if err := migrateNoSmartDNSConfig(path); err != nil { return nil, err }
	return os.ReadFile(path)
}

var noSmartDNSResolverKeys = map[string]bool{
	"nameserver": true, "nameserver-policy": true, "fallback": true,
	"default-nameserver": true, "proxy-server-nameserver": true,
}

func noSmartDNSStaleResolver(n *yaml.Node) bool {
	if n == nil { return false }
	if n.Kind == yaml.ScalarNode {
		v := strings.TrimSpace(strings.Trim(n.Value, "\"'"))
		// Mihomo accepts explicit transport schemes for DNS resolvers. Strip
		// the scheme and optional DoH path before matching retired listeners.
		if schemeEnd := strings.Index(v, "://"); schemeEnd >= 0 {
			scheme := strings.ToLower(v[:schemeEnd])
			switch scheme {
			case "udp", "tcp", "tls", "quic", "http", "https":
				v = v[schemeEnd+3:]
				if pathStart := strings.IndexAny(v, "/?#"); pathStart >= 0 { v = v[:pathStart] }
			}
		}
		v = strings.TrimSpace(v)
		for _, endpoint := range []string{"127.0.0.1:6053", "127.0.0.1:6054", "[::1]:6053", "[::1]:6054", "localhost:6053", "localhost:6054"} {
			if strings.EqualFold(v, endpoint) { return true }
		}
		return false
	}
	for _, child := range n.Content { if noSmartDNSStaleResolver(child) { return true } }
	return false
}

func filterNoSmartDNSResolvers(n *yaml.Node) bool {
	if n == nil { return false }
	changed := false
	if n.Kind == yaml.SequenceNode {
		out := n.Content[:0]
		for _, child := range n.Content {
			if noSmartDNSStaleResolver(child) { changed = true; continue }
			out = append(out, child)
		}
		n.Content = out
		return changed
	}
	if n.Kind == yaml.MappingNode {
		for i := 1; i < len(n.Content); i += 2 {
			value := n.Content[i]
			if value.Kind == yaml.SequenceNode {
				if filterNoSmartDNSResolvers(value) {
					if len(value.Content) == 0 {
						value.Content = []*yaml.Node{
							{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"},
							{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"},
						}
					}
					changed = true
				}
			} else if noSmartDNSStaleResolver(value) {
				// Replace only the stale policy value; unrelated policy entries survive.
				n.Content[i] = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"},
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"},
				}}
				changed = true
			}
		}
	}
	return changed
}

func noSmartDNSMapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode { return nil }
	for i := 0; i+1 < len(n.Content); i += 2 { if n.Content[i].Value == key { return n.Content[i+1] } }
	return nil
}

func secureNoSmartDNSBootstrapResolvers(n *yaml.Node) bool {
	if n == nil { return false }
	changed := false
	if n.Kind == yaml.SequenceNode {
		for _, child := range n.Content { if secureNoSmartDNSBootstrapResolvers(child) { changed = true } }
		return changed
	}
	if n.Kind != yaml.ScalarNode { return false }
	value := strings.TrimSpace(n.Value)
	if strings.Contains(value, "://") { return false }
	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil { return false }
	if ip.To4() == nil {
		n.Value = "tls://[" + ip.String() + "]"
	} else {
		n.Value = "tls://" + ip.String()
	}
	return true
}

func ensureNoSmartDNSProxyAwareDNS(dns *yaml.Node) bool {
	changed := false
	defaultNS := noSmartDNSMapValue(dns, "default-nameserver")
	if defaultNS == nil || (defaultNS.Kind == yaml.SequenceNode && len(defaultNS.Content) == 0) || (defaultNS.Kind == yaml.ScalarNode && strings.TrimSpace(defaultNS.Value) == "") || (defaultNS.Kind != yaml.SequenceNode && defaultNS.Kind != yaml.ScalarNode) {
		defaultNS = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"},
		}}
		if noSmartDNSMapValue(dns, "default-nameserver") == nil {
			dns.Content = append(dns.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "default-nameserver"}, defaultNS)
		} else {
			for i := 0; i+1 < len(dns.Content); i += 2 { if dns.Content[i].Value == "default-nameserver" { dns.Content[i+1] = defaultNS; break } }
		}
		changed = true
	} else if defaultNS.Kind == yaml.ScalarNode {
		defaultNS = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: defaultNS.Value}}}
		for i := 0; i+1 < len(dns.Content); i += 2 { if dns.Content[i].Value == "default-nameserver" { dns.Content[i+1] = defaultNS; break } }
		changed = true
	}
	if secureNoSmartDNSBootstrapResolvers(defaultNS) { changed = true }

	proxyNS := noSmartDNSMapValue(dns, "proxy-server-nameserver")
	if proxyNS == nil || (proxyNS.Kind == yaml.SequenceNode && len(proxyNS.Content) == 0) || (proxyNS.Kind == yaml.ScalarNode && strings.TrimSpace(proxyNS.Value) == "") || (proxyNS.Kind != yaml.SequenceNode && proxyNS.Kind != yaml.ScalarNode) {
		proxyNS = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if defaultNS != nil && defaultNS.Kind == yaml.SequenceNode {
			for _, item := range defaultNS.Content {
				if item != nil && item.Kind == yaml.ScalarNode {
					proxyNS.Content = append(proxyNS.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: item.Value})
				}
			}
		}
		if len(proxyNS.Content) == 0 {
			proxyNS.Content = []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"},
			}
		}
		if noSmartDNSMapValue(dns, "proxy-server-nameserver") == nil {
			dns.Content = append(dns.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxy-server-nameserver"}, proxyNS)
		} else {
			for i := 0; i+1 < len(dns.Content); i += 2 { if dns.Content[i].Value == "proxy-server-nameserver" { dns.Content[i+1] = proxyNS; break } }
		}
		changed = true
	} else if proxyNS.Kind == yaml.ScalarNode {
		proxyNS = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: proxyNS.Value}}}
		for i := 0; i+1 < len(dns.Content); i += 2 { if dns.Content[i].Value == "proxy-server-nameserver" { dns.Content[i+1] = proxyNS; break } }
		changed = true
	}
	if secureNoSmartDNSBootstrapResolvers(proxyNS) { changed = true }

	respectRules := noSmartDNSMapValue(dns, "respect-rules")
	if respectRules == nil {
		dns.Content = append(dns.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "respect-rules"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
		changed = true
	} else if respectRules.Kind != yaml.ScalarNode || !strings.EqualFold(respectRules.Value, "true") {
		respectRules.Kind = yaml.ScalarNode
		respectRules.Tag = "!!bool"
		respectRules.Value = "true"
		respectRules.Content = nil
		changed = true
	}
	return changed
}

func migrateNoSmartDNSConfig(path string) error {
	info, err := os.Lstat(path)
	if err != nil { if os.IsNotExist(err) { return nil }; return err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 { return fmt.Errorf("Mihomo config must be a regular non-symlink file") }
	data, err := os.ReadFile(path); if err != nil { return err }
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil { return fmt.Errorf("parse existing Mihomo config: %w", err) }
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode { return fmt.Errorf("existing Mihomo config is not a YAML mapping") }
	root := doc.Content[0]
	dns := noSmartDNSMapValue(root, "dns")
	if dns == nil { return nil }; if dns.Kind != yaml.MappingNode { return fmt.Errorf("existing Mihomo dns config is not a mapping") }
	changed := false
	for i := 0; i+1 < len(dns.Content); i += 2 {
		key := dns.Content[i].Value
		if !noSmartDNSResolverKeys[key] { continue }
		value := dns.Content[i+1]
		if key == "nameserver" && value.Kind != yaml.SequenceNode && noSmartDNSStaleResolver(value) {
			dns.Content[i+1] = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"},
			}}
			changed = true
			continue
		}
		if filterNoSmartDNSResolvers(value) { changed = true }
	}
	// Route regular DNS upstreams through Mihomo rules. Bootstrap resolvers remain
	// independent of the proxy handshake and use DoT to avoid plaintext DNS leaks.
	if ensureNoSmartDNSProxyAwareDNS(dns) { changed = true }
	// Guarantee a usable default resolver if a legacy policy left nameserver empty.
	ns := noSmartDNSMapValue(dns, "nameserver")
	if ns == nil || (ns.Kind == yaml.SequenceNode && len(ns.Content) == 0) {
		if ns == nil { dns.Content = append(dns.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "nameserver"}, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"}}}) } else {
			ns.Content = []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"}}
		}
		changed = true
	}
	if !changed { return nil }
	backup := path + ".pre-no-smartdns"
	if _, err := os.Lstat(backup); os.IsNotExist(err) {
		bf, createErr := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil { return fmt.Errorf("create one-time config backup: %w", createErr) }
		if _, writeErr := bf.Write(data); writeErr != nil { bf.Close(); return writeErr }
		if syncErr := bf.Sync(); syncErr != nil { bf.Close(); return syncErr }
		if closeErr := bf.Close(); closeErr != nil { return closeErr }
	} else if err != nil { return err }
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out); enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil { return err }
	if err := enc.Close(); err != nil { return err }
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-no-smartdns-*"); if err != nil { return err }
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil { tmp.Close(); return err }
	if _, err := tmp.Write(out.Bytes()); err != nil { tmp.Close(); return err }
	if err := tmp.Sync(); err != nil { tmp.Close(); return err }
	if err := tmp.Close(); err != nil { return err }
	if err := os.Rename(tmpName, path); err != nil { return err }
	d, err := os.Open(dir); if err != nil { return err }; defer d.Close()
	return d.Sync()
}
