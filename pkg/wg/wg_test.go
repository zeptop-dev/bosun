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
