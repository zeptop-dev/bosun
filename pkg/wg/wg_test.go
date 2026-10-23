package wg

import "testing"

func TestKeysAndDerivation(t *testing.T) {
	priv, pub, err := Keypair()
	if err != nil {
		t.Fatal(err)
	}
	if p2, _ := PublicKey(priv); p2 != pub {
		t.Fatal("public key mismatch")
	}
	a1, ap1, _ := DerivePeer(priv, "user-a")
	a2, ap2, _ := DerivePeer(priv, "user-a")
	b1, _, _ := DerivePeer(priv, "user-b")
	if a1 != a2 || ap1 != ap2 || a1 == b1 {
		t.Fatal("derivation must be deterministic per user and distinct")
	}
	if p, _ := PublicKey(a1); p != ap1 {
		t.Fatal("derived public key mismatch")
	}
	if ClientAddress(1) != "10.66.0.3/32" || ClientAddress(253) != "10.66.1.1/32" {
		t.Fatalf("addresses: %s %s", ClientAddress(1), ClientAddress(253))
	}
}

func TestDeviceKeysAndAddressIsolation(t *testing.T) {
	server, _, err := Keypair()
	if err != nil {
		t.Fatal(err)
	}
	first, pub, err := DeriveDevicePeer(server, "account", "phone")
	if err != nil {
		t.Fatal(err)
	}
	again, _, _ := DeriveDevicePeer(server, "account", "phone")
	laptop, _, _ := DeriveDevicePeer(server, "account", "laptop")
	rotated, _, _ := DeriveDevicePeer(server, "rotated-account", "phone")
	legacy, _, _ := DerivePeer(server, "account")
	if first != again || first == laptop || first == rotated || first == legacy {
		t.Fatal("device identity is unstable or collides with another identity")
	}
	if expected, _ := PublicKey(first); expected != pub {
		t.Fatal("device public key does not match")
	}
	for id, want := range map[int64]string{1: "10.67.0.1/32", 256: "10.67.1.0/32", 65534: "10.67.255.254/32"} {
		if got, err := DeviceAddress(id); err != nil || got != want {
			t.Fatalf("device address %d = %q: %v", id, got, err)
		}
	}
	for _, id := range []int64{-1, 0, 65535, 1 << 40} {
		if _, err := DeviceAddress(id); err == nil {
			t.Fatal("invalid device id wrapped around the pool")
		}
	}
	if _, _, err := DeriveDevicePeer(server, "account", ""); err == nil {
		t.Fatal("empty device identity accepted")
	}
}
