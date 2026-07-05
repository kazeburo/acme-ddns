package ddns

import (
	"net"
	"reflect"
	"testing"
)

// test NewDDNS with options
func TestNewDDNS(t *testing.T) {
	zone := "example.com"
	nsName := "ns"
	nsAddr := net.ParseIP("192.168.0.1")
	tsigSecretMap := map[string]string{
		"example-key.": "example-secret",
	}
	ddns, err := New(
		TsigSecretMap(tsigSecretMap),
		Zone(zone),
		NSName(nsName),
		NSAddr(nsAddr),
	)
	if err != nil {
		t.Fatalf("NewDDNS failed: %v", err)
	}
	if ddns.Zone != "example.com." {
		t.Errorf("Zone mismatch: got %s, want %s", ddns.Zone, "example.com.")
	}
	if ddns.NSName != "ns.example.com." {
		t.Errorf("NSName mismatch: got %s, want %s", ddns.NSName, "ns.example.com.")
	}
	if !ddns.NSAddr.Equal(nsAddr) {
		t.Errorf("NSAddr mismatch: got %v, want %v", ddns.NSAddr, nsAddr)
	}
	if !reflect.DeepEqual(ddns.TsigSecretMap, tsigSecretMap) {
		t.Errorf("TsigSecretMap mismatch: got %v, want %v", ddns.TsigSecretMap, tsigSecretMap)
	}
	if ddns.Cache == nil {
		t.Errorf("Cache is nil, expected a non-nil cache")
	}
	if ddns.Logger == nil {
		t.Errorf("Logger is nil, expected a non-nil logger")
	}
}

// test NewDDNS with missing required options
func TestNewDDNSMissingRequiredOptions(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatalf("NewDDNS should fail when required options are missing")
	}
}

// test NewDDNS with NSName already fully-qualified
func TestNewDDNSNSNameAlreadyQualified(t *testing.T) {
	ddns, err := New(
		Zone("example.com"),
		NSName("ns.example.com."),
	)
	if err != nil {
		t.Fatalf("NewDDNS failed: %v", err)
	}
	if ddns.NSName != "ns.example.com." {
		t.Errorf("NSName mismatch: got %s, want %s", ddns.NSName, "ns.example.com.")
	}
}

// test tsigEnabled method
func TestTsigEnabled(t *testing.T) {
	ddns := &DDNS{
		TsigSecretMap: map[string]string{
			"example-key.": "example-secret",
		},
	}
	if !ddns.tsigEnabled() {
		t.Errorf("tsigEnabled should return true when TsigSecretMap is set")
	}

	ddnsEmpty := &DDNS{
		TsigSecretMap: map[string]string{},
	}
	if ddnsEmpty.tsigEnabled() {
		t.Errorf("tsigEnabled should return false when TsigSecretMap is empty")
	}

	ddnsNil := &DDNS{}
	if ddnsNil.tsigEnabled() {
		t.Errorf("tsigEnabled should return false when TsigSecretMap is nil")
	}
}
