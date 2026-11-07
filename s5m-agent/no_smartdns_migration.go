package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var noSmartDNSResolverKeys = map[string]bool{
	"nameserver": true, "nameserver-policy": true, "fallback": true,
	"default-nameserver": true, "proxy-server-nameserver": true,
}

func noSmartDNSStaleResolver(n *yaml.Node) bool {
	if n == nil { return false }
	if n.Kind == yaml.ScalarNode {
		v := strings.TrimSpace(strings.Trim(n.Value, "\"'"))
		for _, endpoint := range []string{"127.0.0.1:6053", "127.0.0.1:6054", "[::1]:6053", "[::1]:6054", "localhost:6053", "localhost:6054"} {
			if v == endpoint { return true }
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
			if noSmartDNSStaleResolver(n.Content[i]) {
				// Keep mapping keys but replace stale policy values with safe resolvers.
				n.Content[i] = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.5.5.5"},
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.6.6.6"},
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
		if key == "nameserver" && noSmartDNSStaleResolver(value) {
			dns.Content[i+1] = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.5.5.5"},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.6.6.6"},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "1.1.1.1"},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "8.8.8.8"},
			}}
			changed = true
			continue
		}
		if filterNoSmartDNSResolvers(value) { changed = true }
	}
	// Guarantee a usable default resolver if a legacy policy left nameserver empty.
	ns := noSmartDNSMapValue(dns, "nameserver")
	if ns == nil || (ns.Kind == yaml.SequenceNode && len(ns.Content) == 0) {
		if ns == nil { dns.Content = append(dns.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "nameserver"}, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.5.5.5"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.6.6.6"}}}) } else {
			ns.Content = []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.5.5.5"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.6.6.6"}}
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
