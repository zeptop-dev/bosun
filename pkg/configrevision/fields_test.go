package configrevision

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type testInput struct {
	Node     spec.Node
	Forwards []spec.Forward
}
type classification struct{ path, structural, excluded, opaque string }

// This inventory is intentionally exhaustive for every projected spec type.
// Excluded subtrees (users, credentials, service control) never enter the DTO;
// their leaf inventories additionally verify today's material classifications.
var classifications = []classification{
	{"Node", "Mode WireGuardLinks EgressUpstreams ReverseClients Inbounds Outbounds Routes DefaultOutbound ConnLog AllowPrivateDest PrivateDestAllow EgressByIngress AuditRules DNS Decoy", "ID ModeRevision ServiceControl Forwards ACME Certificates UserSpeedLimitMbps", "Overrides"},
	{"Node.Inbounds[]", "WireGuardSlot PrivateAccess Reverse Tag Protocol Listen Port Core TLS Transport Multiplex Flow Cipher Obfs UpMbps DownMbps CongestionControl PaddingScheme MieruTransport TrafficPattern MieruMTU MieruMultiplexing MieruHandshake WGAddress WGMTU SnellVersion SnellObfs SnellObfsHost ShadowTLS SnellMultiUser NoSniff AcceptProxyProtocol Fallbacks", "SSH ServerKey ObfsPassword WGPrivateKey WGPublicKey SnellPSK ScopedUsers Users", ""},
	{"Node.Inbounds[].TLS", "Mode ServerName ALPN Reality AutoCert ACME", "CertPath KeyPath", ""},
	{"Node.Inbounds[].TLS.Reality", "HandshakeServer HandshakePort FallbackLimit", "PrivateKey PublicKey ShortIDs", ""},
	{"Node.Inbounds[].TLS.Reality.FallbackLimit", "Off AfterBytes BytesPerSec BurstBytesPerSec", "", ""},
	{"Node.Inbounds[].Transport", "Type Path Host ServiceName Mode", "", ""},
	{"Node.Inbounds[].Multiplex", "Enabled Padding Brutal", "", ""},
	{"Node.Inbounds[].Multiplex.Brutal", "UpMbps DownMbps", "", ""},
	{"Node.Inbounds[].Fallbacks[]", "Name ALPN Path Dest Xver", "", ""},
	{"Node.Inbounds[].ShadowTLS", "Handshake StrictMode", "", ""},
	{"Node.Inbounds[].PrivateAccess", "AllowCoreOnly Enforcement Mode Rules", "", ""},
	{"Node.Inbounds[].PrivateAccess.Rules[]", "CIDR Protocol PortStart PortEnd", "", ""},
	{"Node.Inbounds[].Reverse", "ID Receiver", "UUID", ""},
	{"Node.Inbounds[].SSH", "", "PrivateKey PublicKey", ""},
	{"Node.Inbounds[].Users[]", "", "ID Name UUID Password SpeedLimitMbps DeviceLimit WireGuardPeers WireGuardLegacyDisabled QuotaBytes QuotaDays", ""},
	{"Node.Inbounds[].Users[].WireGuardPeers[]", "", "UUID Address", ""},
	{"Node.ReverseClients[]", "PrivateAccess ID Host Port TLS", "UUID", ""},
	{"Node.WireGuardLinks[]", "Slot Exit Endpoint ListenPort MTU PrivateAccess DomainPreference AutoForwarding", "PrivateKey PeerKey", ""},
	{"Node.EgressUpstreams[]", "CIDR Protocol Port", "", ""},
	{"Node.Outbounds[]", "Tag Protocol ProxyTag Remote WARP Balancer", "", "Settings"},
	{"Node.Outbounds[].Remote", "Host Port Insecure Fingerprint Settings", "SSH UUID Password Username", ""},
	{"Node.Outbounds[].Remote.SSH", "", "PrivateKey HostKey", ""},
	{"Node.Outbounds[].WARP", "FromNode Endpoint Addresses", "PrivateKey PeerPublicKey Reserved License", ""},
	{"Node.Outbounds[].Balancer", "Members Strategy", "", ""},
	{"Node.Routes[]", "Match Action Value", "", ""},
	{"Node.AuditRules[]", "ID Match Action", "Name", ""},
	{"Forwards[]", "Tag Listen Port Protocol Target Backend PreserveSource ProxyProtocol Targets Balance Weight", "IngressID", ""},
	{"Forwards[].Targets[]", "Target Weight", "", ""},
	{"Node.Decoy", "Domain Port Upstream ACME AllowPrivate Insecure", "", ""},
	{"Node.ACME", "", "Email CloudflareToken", ""},
	{"Node.Certificates[]", "", "Domain CertPEM KeyPEM", ""},
	{"Node.ServiceControl", "", "Offline Revision Mode LimitMbps", ""},
}

// atPath creates only the containers needed to reach a classified source type.
func atPath(in *testInput, path string) reflect.Value {
	v := reflect.ValueOf(in).Elem()
	for _, name := range strings.Split(path, ".") {
		slice := strings.HasSuffix(name, "[]")
		v = v.FieldByName(strings.TrimSuffix(name, "[]"))
		if slice {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			v = v.Index(0)
		}
		if v.Kind() == reflect.Pointer {
			v.Set(reflect.New(v.Type().Elem()))
			v = v.Elem()
		}
	}
	return v
}
func classificationTypes() map[reflect.Type]classification {
	m := map[reflect.Type]classification{}
	for _, c := range classifications {
		var in testInput
		m[atPath(&in, c.path).Type()] = c
	}
	return m
}
func makeNonzero(v reflect.Value, types map[reflect.Type]classification) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("changed")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(2)
	case reflect.Uint64:
		v.SetUint(2)
	case reflect.Uint8:
		v.SetUint(2)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		makeNonzero(v.Elem(), types)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		makeNonzero(v.Index(0), types)
	case reflect.Struct:
		name := ""
		if c, ok := types[v.Type()]; ok {
			if fs := strings.Fields(c.structural); len(fs) > 0 {
				name = fs[0]
			}
		}
		if name != "" {
			makeNonzero(v.FieldByName(name), types)
		} else {
			makeNonzero(v.Field(0), types)
		}
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		val := reflect.New(v.Type().Elem()).Elem()
		makeNonzero(val, types)
		v.SetMapIndex(reflect.ValueOf("opaque"), val)
	case reflect.Interface:
		v.Set(reflect.ValueOf("opaque-credential"))
	default:
		panic("unhandled test field kind: " + v.Type().String())
	}
}

func TestEverySourceFieldHasAnExplicitClassification(t *testing.T) {
	types := classificationTypes()
	for typ, c := range types {
		t.Run(typ.Name(), func(t *testing.T) {
			fields := map[string]string{}
			for kind, names := range map[string]string{"structural": c.structural, "excluded": c.excluded, "opaque": c.opaque} {
				for _, name := range strings.Fields(names) {
					if _, ok := typ.FieldByName(name); !ok || fields[name] != "" {
						t.Fatalf("unknown/duplicate field classification: %s.%s", typ, name)
					}
					fields[name] = kind
				}
			}
			for i := 0; i < typ.NumField(); i++ {
				if fields[typ.Field(i).Name] == "" {
					t.Errorf("new field needs explicit classification: %s.%s", typ, typ.Field(i).Name)
				}
			}
			for name, kind := range fields {
				t.Run(name, func(t *testing.T) {
					var in testInput
					v := atPath(&in, c.path)
					before, err := Digest(in.Node, in.Forwards)
					if err != nil {
						t.Fatal(err)
					}
					makeNonzero(v.FieldByName(name), types)
					after, err := Digest(in.Node, in.Forwards)
					if kind == "opaque" {
						if !errors.Is(err, ErrUnsupported) || after != "" {
							t.Fatalf("opaque field accepted: %s %v", after, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if (before != after) != (kind == "structural") {
						t.Fatalf("field classified %s but digest changed=%v", kind, before != after)
					}
				})
			}
		})
	}
	// Every recursively projected spec struct must have its own reviewed fields.
	var walk func(reflect.Type)
	seen := map[reflect.Type]bool{}
	walk = func(typ reflect.Type) {
		if typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			walk(typ.Elem())
			return
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		c, ok := types[typ]
		if !ok {
			t.Fatalf("unclassified projected spec type: %s", typ)
		}
		for _, name := range strings.Fields(c.structural) {
			f, _ := typ.FieldByName(name)
			walk(f.Type)
		}
	}
	walk(reflect.TypeFor[spec.Node]())
	walk(reflect.TypeFor[spec.Forward]())
}

func TestProjectionCannotEmbedUnreviewedSourceData(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		if strings.HasSuffix(typ.PkgPath(), "/pkg/spec") || typ.Kind() == reflect.Interface || typ.Kind() == reflect.Map {
			t.Fatalf("unreviewed source data in projection: %s", typ)
		}
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice:
			walk(typ.Elem())
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				walk(typ.Field(i).Type)
			}
		}
	}
	walk(reflect.TypeFor[projection]())
}
