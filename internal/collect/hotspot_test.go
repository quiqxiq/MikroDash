package collect

import (
	"strings"
	"testing"
	"time"

	"mikrodash/internal/routeros"
)

func TestParseHotspotActiveRates(t *testing.T) {
	t0 := time.UnixMilli(1700000000000)
	t1 := t0.Add(5 * time.Second)

	rows0 := []routeros.Reply{
		{".id": "*1", "user": "voucher10", "address": "192.168.88.10", "bytes-in": "1000", "bytes-out": "2000"},
	}

	sessions0, prev0 := ParseHotspotActive(rows0, nil, t0)
	if len(sessions0) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions0))
	}
	if sessions0[0].RXRate != nil || sessions0[0].TXRate != nil {
		t.Fatalf("first sample must have nil rates, got %v, %v", sessions0[0].RXRate, sessions0[0].TXRate)
	}

	rows1 := []routeros.Reply{
		{".id": "*1", "user": "voucher10", "address": "192.168.88.10", "bytes-in": "6000", "bytes-out": "12000"},
	}
	sessions1, _ := ParseHotspotActive(rows1, prev0, t1)
	if len(sessions1) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions1))
	}
	if sessions1[0].RXRate == nil || sessions1[0].TXRate == nil {
		t.Fatal("second sample must have calculated rates")
	}
	// dt = 5s, diff RX = 5000 bytes => 1000 B/s; diff TX = 10000 bytes => 2000 B/s
	if *sessions1[0].RXRate != 1000 || *sessions1[0].TXRate != 2000 {
		t.Errorf("expected RX=1000 TX=2000, got RX=%v TX=%v", *sessions1[0].RXRate, *sessions1[0].TXRate)
	}
}

func TestBuildHotspotInactiveUsers(t *testing.T) {
	now := time.Now()
	activeRows := []routeros.Reply{
		{".id": "*1", "user": "alice", "address": "192.168.88.10", "mac-address": "00:11:22:33:44:55", "uptime": "10m", "bytes-in": "100", "bytes-out": "200"},
	}
	allUsers := []HotspotUser{
		{ID: "*u1", Name: "alice", Profile: "default"},
		{ID: "*u2", Name: "bob", Profile: "vip", Disabled: false},
		{ID: "*u3", Name: "charlie", Profile: "default", Disabled: true},
	}

	pl, _, _ := BuildHotspot(HotspotInput{
		Rows:  activeRows,
		Prev:  map[string]hotspotSample{},
		Users: allUsers,
		Now:   now,
	})

	if len(pl.Users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(pl.Users))
	}

	// alice is active
	if !pl.Users[0].Connected || pl.Users[0].ActiveIP != "192.168.88.10" {
		t.Errorf("alice should be connected with IP 192.168.88.10, got %v (%s)", pl.Users[0].Connected, pl.Users[0].ActiveIP)
	}

	// bob is inactive
	if pl.Users[1].Connected {
		t.Errorf("bob should be inactive, got connected=true")
	}

	// charlie is inactive (and disabled)
	if pl.Users[2].Connected {
		t.Errorf("charlie should be inactive, got connected=true")
	}
}

func TestHotspotUserProplistOmitsPassword(t *testing.T) {
	for _, arg := range hotspotUserCmd.Args {
		if strings.Contains(arg, "password") {
			t.Fatalf("hotspotUserCmd must never request password, found: %s", arg)
		}
	}
}
