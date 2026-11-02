package app

import (
	"path/filepath"
	"testing"
)

func seedBulkProxy(t *testing.T, store *Store, name, machineCode string) int64 {
	t.Helper()
	p := &Proxy{Name: name, Type: "socks5", Server: "127.0.0.1", Port: 1080, SourceCIDR: "0.0.0.0/0", MachineCode: machineCode, Extra: map[string]any{}, Enabled: true}
	if err := store.CreateProxy(p); err != nil { t.Fatalf("CreateProxy(%q): %v", name, err) }
	return p.ID
}

func TestBindProxiesToMachineUpdatesOnlySelectedRows(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-bulk-bind.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	first := seedBulkProxy(t, store, "proxy-a", "")
	second := seedBulkProxy(t, store, "proxy-b", "__GLOBAL__")
	other := seedBulkProxy(t, store, "proxy-c", "node-other")

	if err := store.BindProxiesToMachine([]int64{first, second}, "node-target"); err != nil {
		t.Fatalf("BindProxiesToMachine: %v", err)
	}
	for id, want := range map[int64]string{first:"node-target", second:"node-target", other:"node-other"} {
		got, err := store.GetProxy(id)
		if err != nil { t.Fatalf("GetProxy(%d): %v", id, err) }
		if got.MachineCode != want { t.Errorf("proxy %d machine_code=%q, want %q", id, got.MachineCode, want) }
	}
}

func TestBindProxiesToMachineRollsBackOnMissingProxy(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-bulk-bind-rollback.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	id := seedBulkProxy(t, store, "proxy-a", "")
	if err := store.BindProxiesToMachine([]int64{id, 999999}, "node-target"); err == nil {
		t.Fatal("expected missing proxy to abort the batch")
	}
	got, err := store.GetProxy(id)
	if err != nil { t.Fatalf("GetProxy: %v", err) }
	if got.MachineCode != "" { t.Fatalf("partial association committed: machine_code=%q", got.MachineCode) }
}

func TestDeleteProxiesDeletesSelectedRowsOnly(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-bulk-delete.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	first := seedBulkProxy(t, store, "proxy-a", "")
	second := seedBulkProxy(t, store, "proxy-b", "node-b")
	keep := seedBulkProxy(t, store, "proxy-keep", "node-keep")

	if err := store.DeleteProxies([]int64{first, second}); err != nil {
		t.Fatalf("DeleteProxies: %v", err)
	}
	if _, err := store.GetProxy(first); err == nil { t.Fatal("first selected proxy still exists") }
	if _, err := store.GetProxy(second); err == nil { t.Fatal("second selected proxy still exists") }
	if got, err := store.GetProxy(keep); err != nil || got.Name != "proxy-keep" {
		t.Fatalf("unselected proxy changed: got=%#v err=%v", got, err)
	}
}


func TestDeleteProxiesRollsBackWhenAnyProxyIsMissing(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-bulk-delete-rollback.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	first := seedBulkProxy(t, store, "proxy-a", "")
	if err := store.DeleteProxies([]int64{first, 999999}); err == nil {
		t.Fatal("expected missing proxy to abort the batch")
	}
	if got, err := store.GetProxy(first); err != nil || got.Name != "proxy-a" {
		t.Fatalf("partial deletion committed: got=%#v err=%v", got, err)
	}
}

func TestDeleteProxiesRejectsDuplicateIDsWithoutDeleting(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-bulk-delete-duplicate.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	id := seedBulkProxy(t, store, "proxy-a", "")
	if err := store.DeleteProxies([]int64{id, id}); err == nil {
		t.Fatal("expected duplicate IDs to be rejected")
	}
	if got, err := store.GetProxy(id); err != nil || got.Name != "proxy-a" {
		t.Fatalf("duplicate request deleted proxy: got=%#v err=%v", got, err)
	}
}

func TestDeleteProxiesRejectsInvalidIDsBeforeMutation(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-bulk-delete-invalid.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	id := seedBulkProxy(t, store, "proxy-a", "")
	if err := store.DeleteProxies([]int64{id, 0}); err == nil {
		t.Fatal("expected invalid ID to be rejected")
	}
	if got, err := store.GetProxy(id); err != nil || got.Name != "proxy-a" {
		t.Fatalf("invalid ID request deleted proxy: got=%#v err=%v", got, err)
	}
}
