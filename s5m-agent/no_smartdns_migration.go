package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// normalizeNoSmartDNSBootstrapResolver accepts only encrypted DoT endpoints
// whose destination is a literal IP. Hostnames would require a second bootstrap
// lookup, while udp/tcp/http schemes would bypass the encrypted-bootstrap policy.
func normalizeNoSmartDNSBootstrapResolver(raw string) (string, bool) {
	value := strings.TrimSpace(strings.Trim(raw, "\"'"))
	if value == "" {
		return "", false
	}
	scheme := ""
	if i := strings.Index(value, "://"); i >= 0 {
		scheme = strings.ToLower(value[:i])
		value = value[i+3:]
		if scheme != "tls" {
			return "", false
		}
	}
	if strings.ContainsAny(value, "/?#@") {
		return "", false
	}
	host := value
	port := ""
	if strings.HasPrefix(value, "[") {
		if h, p, err := net.SplitHostPort(value); err == nil {
			host, port = h, p
		} else {
			host = strings.Trim(value, "[]")
		}
	} else if strings.Count(value, ":") == 1 {
		if h, p, err := net.SplitHostPort(value); err == nil {
			host, port = h, p
		}
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "", false
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", false
		}
	}
	endpoint := ip.String()
	if ip.To4() == nil {
		endpoint = "[" + endpoint + "]"
	}
	if port != "" {
		endpoint = net.JoinHostPort(strings.Trim(ip.String(), "[]"), port)
	}
	return "tls://" + endpoint, true
}

func secureNoSmartDNSBootstrapResolvers(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	defaults := func() []*yaml.Node {
		return []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"},
		}
	}
	if n.Kind == yaml.ScalarNode {
		normalized, ok := normalizeNoSmartDNSBootstrapResolver(n.Value)
		if ok {
			if n.Value != normalized {
				n.Value = normalized
				return true
			}
			return false
		}
		n.Kind, n.Tag, n.Value = yaml.SequenceNode, "!!seq", ""
		n.Content = defaults()
		return true
	}
	if n.Kind != yaml.SequenceNode {
		n.Kind, n.Tag = yaml.SequenceNode, "!!seq"
		n.Content = defaults()
		return true
	}
	changed := false
	seen := make(map[string]bool, len(n.Content))
	kept := make([]*yaml.Node, 0, len(n.Content))
	for _, child := range n.Content {
		if child == nil || child.Kind != yaml.ScalarNode {
			changed = true
			continue
		}
		normalized, ok := normalizeNoSmartDNSBootstrapResolver(child.Value)
		if !ok || seen[normalized] {
			changed = true
			continue
		}
		if child.Value != normalized {
			child.Value = normalized
			changed = true
		}
		seen[normalized] = true
		kept = append(kept, child)
	}
	if len(kept) == 0 {
		kept = defaults()
		changed = true
	}
	n.Content = kept
	return changed
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


func removeNoSmartDNSRouting(root *yaml.Node) bool {
	if root == nil || root.Kind != yaml.MappingNode { return false }
	changed := false
	rules := noSmartDNSMapValue(root, "rules")
	if rules != nil && rules.Kind == yaml.SequenceNode {
		filtered := rules.Content[:0]
		for _, rule := range rules.Content {
			if rule != nil && rule.Kind == yaml.ScalarNode {
				parts := strings.Split(rule.Value, ",")
				if len(parts) >= 3 && strings.EqualFold(strings.TrimSpace(parts[0]), "PROCESS-NAME") &&
					strings.EqualFold(strings.TrimSpace(parts[1]), "smartdns") {
					changed = true
					continue
				}
			}
			filtered = append(filtered, rule)
		}
		rules.Content = filtered
	}
	groups := noSmartDNSMapValue(root, "proxy-groups")
	if groups == nil || groups.Kind != yaml.SequenceNode { return changed }
	// Remove the reserved group only when no remaining rule or proxy group
	// references it. A user may have deliberately reused this group name.
	for i := 0; i < len(groups.Content); {
		group := groups.Content[i]
		name := noSmartDNSMapValue(group, "name")
		if name == nil || name.Kind != yaml.ScalarNode || name.Value != "SMARTDNS-PROXY" {
			i++
			continue
		}
		used := false
		for _, section := range []*yaml.Node{rules, groups} {
			if section == nil { continue }
			for _, entry := range section.Content {
				if entry == group { continue }
				if entry.Kind == yaml.ScalarNode && strings.Contains(entry.Value, "SMARTDNS-PROXY") { used = true }
				if entry.Kind == yaml.MappingNode {
					for j := 1; j < len(entry.Content); j += 2 {
						value := entry.Content[j]
						if value.Kind == yaml.ScalarNode && value.Value == "SMARTDNS-PROXY" { used = true }
						if value.Kind == yaml.SequenceNode {
							for _, item := range value.Content {
								if item.Kind == yaml.ScalarNode && item.Value == "SMARTDNS-PROXY" { used = true }
							}
						}
					}
				}
			}
		}
		if used { i++; continue }
		groups.Content = append(groups.Content[:i], groups.Content[i+1:]...)
		changed = true
	}
	return changed
}

// validateNoSmartDNSBackup rejects symlinks, special files, and backups that
// are readable by group/other users. A backup is the recovery point for the
// user's original Mihomo configuration, so an unsafe pre-existing path must
// never be treated as a successful backup.
func validateNoSmartDNSBackup(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup path is not a regular non-symlink file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("backup permissions are not private")
	}
	if info.Size() == 0 {
		return fmt.Errorf("backup file is empty")
	}
	return nil
}

// createNoSmartDNSBackup publishes the original config atomically without
// replacing an existing one-time backup. The temporary file is created in the
// same directory so the hard-link publication is atomic and cannot expose a
// partially written backup after a crash.
func createNoSmartDNSBackup(path string, data []byte) error {
	if err := validateNoSmartDNSBackup(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pre-no-smartdns-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			// Another process may have completed the backup concurrently.
			return validateNoSmartDNSBackup(path)
		}
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
	changed := removeNoSmartDNSRouting(root)
	dns := noSmartDNSMapValue(root, "dns")
	if dns == nil {
		if !changed { return nil }
	} else if dns.Kind != yaml.MappingNode {
		return fmt.Errorf("existing Mihomo dns config is not a mapping")
	}
	if dns != nil {
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
	}
	// Route regular DNS upstreams through Mihomo rules. Bootstrap resolvers remain
	// independent of the proxy handshake and use DoT to avoid plaintext DNS leaks.
	if dns != nil && ensureNoSmartDNSProxyAwareDNS(dns) { changed = true }
	// Guarantee a usable default resolver if a legacy policy left nameserver empty.
	if dns != nil {
		ns := noSmartDNSMapValue(dns, "nameserver")
		if ns == nil || (ns.Kind == yaml.SequenceNode && len(ns.Content) == 0) {
		if ns == nil { dns.Content = append(dns.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "nameserver"}, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"}}}) } else {
			ns.Content = []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.5.5.5"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "tls://223.6.6.6"}}
		}
			changed = true
		}
	}
	if !changed { return nil }
	backup := path + ".pre-no-smartdns"
	if err := createNoSmartDNSBackup(backup, data); err != nil {
		return fmt.Errorf("create or validate one-time config backup: %w", err)
	}
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
