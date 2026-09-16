// Package coreinstall knows which upstream core releases bosun has tested and
// can fetch, verify and install them. The manifest is the version whitelist:
// bosun never picks "latest", it picks the newest release marked tested.
package coreinstall

import "sort"

// Status describes how much trust a release has earned.
type Status string

const (
	StatusTested  Status = "tested"  // used in bosun's end-to-end tests
	StatusCaution Status = "caution" // works, with a documented limitation
	StatusBroken  Status = "broken"  // known to break real deployments
)

// Asset is one downloadable build of a release. Either SHA256 pins the
// digest in the manifest, or SumsURL points at a SHA256SUMS file published
// next to the asset (used for builds bosun's own CI produces).
type Asset struct {
	URL     string
	SHA256  string
	SumsURL string
	Archive string // "tar.gz", "zip" or "raw"
	Member  string // file inside the archive; ignored for raw
}

// Build describes building the upstream module with the Go toolchain. It is
// the fallback when no Asset exists for the platform, and the only option for
// sing-box because upstream release binaries omit the stats API bosun needs.
type Build struct {
	Package string   // e.g. github.com/sagernet/sing-box/cmd/sing-box
	Version string   // module version, e.g. v1.14.0
	Tags    []string // build tags
	LDFlags string   // extra -ldflags, e.g. to stamp the version string
}

// Release is one upstream version of one core.
type Release struct {
	Core    string
	Version string
	Status  Status
	Note    string
	Assets  map[string]Asset // key: GOOS/GOARCH
	Build   *Build
}

// Binary is the executable file name per core.
var Binary = map[string]string{
	"singbox":  "sing-box",
	"xray":     "xray",
	"mita":     "mita",
	"hysteria": "hysteria",
	"snell":    "snell-server",
	"realm":    "realm",
}

var singboxTags = []string{"with_quic", "with_utls", "with_clash_api", "with_v2ray_api", "with_gvisor", "with_acme", "with_wireguard"}

// singboxCI points at the sing-box builds the bosun CI publishes as a
// GitHub pre-release tagged singbox-<version> (workflow singbox.yml).
// RegistryBase is where bosun's own CI-built assets live; the optional
// registry token is sent there and nowhere else.
const RegistryBase = "https://github.com/zeptop-dev/bosun/releases/download/"

func singboxCI(version, arch string) Asset {
	base := "https://github.com/zeptop-dev/bosun/releases/download/singbox-" + version + "/"
	return Asset{URL: base + "sing-box-" + version + "-linux-" + arch, SumsURL: base + "SHA256SUMS", Archive: "raw"}
}

// Manifest lists every release bosun knows about. Newest first per core.
var Manifest = []Release{
	{
		// -r2: same upstream source rebuilt with with_wireguard, which the
		// WARP outbound and WireGuard endpoints need (the first build
		// failed sing-box's check with "WireGuard is not included").
		Core: "singbox", Version: "1.14.0-r2", Status: StatusTested,
		Note: "upstream v1.14.0 built by bosun CI with with_v2ray_api (per-user stats) and with_wireguard (WARP)",
		Assets: map[string]Asset{
			"linux/amd64": singboxCI("1.14.0-r2", "amd64"),
			"linux/arm64": singboxCI("1.14.0-r2", "arm64"),
		},
		Build: &Build{Package: "github.com/sagernet/sing-box/cmd/sing-box", Version: "v1.14.0", Tags: singboxTags,
			LDFlags: "-X github.com/sagernet/sing-box/constant.Version=1.14.0"},
	},
	{
		Core: "singbox", Version: "1.14.0", Status: StatusCaution,
		Note: "first bosun CI build without with_wireguard: WARP outbounds fail; use 1.14.0-r2",
		Assets: map[string]Asset{
			"linux/amd64": singboxCI("1.14.0", "amd64"),
			"linux/arm64": singboxCI("1.14.0", "arm64"),
		},
		Build: &Build{Package: "github.com/sagernet/sing-box/cmd/sing-box", Version: "v1.14.0", Tags: singboxTags,
			LDFlags: "-X github.com/sagernet/sing-box/constant.Version=1.14.0"},
	},
	{
		Core: "xray", Version: "26.9.9", Status: StatusBroken,
		Note: "REALITY rejects mihomo 1.19.30 and sing-box 1.14.0 clients (xtls/reality 8cdf7bf requires X25519MLKEM768 first)",
		Assets: map[string]Asset{
			"linux/amd64":  {URL: "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-64.zip", Archive: "zip", Member: "xray"},
			"linux/arm64":  {URL: "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-arm64-v8a.zip", Archive: "zip", Member: "xray"},
			"darwin/arm64": {URL: "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-macos-arm64-v8a.zip", Archive: "zip", Member: "xray"},
		},
	},
	{
		Core: "xray", Version: "26.3.27", Status: StatusTested,
		Note: "REALITY verified with mihomo 1.19.30 and sing-box 1.14.0 clients",
		Assets: map[string]Asset{
			"linux/amd64":  {URL: "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip", SHA256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae", Archive: "zip", Member: "xray"},
			"linux/arm64":  {URL: "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip", SHA256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c", Archive: "zip", Member: "xray"},
			"darwin/arm64": {URL: "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-macos-arm64-v8a.zip", SHA256: "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf", Archive: "zip", Member: "xray"},
		},
	},
	{
		Core: "mita", Version: "3.36.1", Status: StatusTested,
		Note: "official mieru server; verified with the official mieru client",
		Assets: map[string]Asset{
			"linux/amd64": {URL: "https://github.com/enfein/mieru/releases/download/v3.36.1/mita_3.36.1_linux_amd64.tar.gz", SHA256: "8e6ae525bbcaa688a8446aebf3c2ecbcb4ce606838d23edfa3f7f2fad506a8f7", Archive: "tar.gz", Member: "mita"},
			"linux/arm64": {URL: "https://github.com/enfein/mieru/releases/download/v3.36.1/mita_3.36.1_linux_arm64.tar.gz", SHA256: "cbdae447b5bcf0ebc1c41c46b6638ce91c5d61b35eb43bc3bdc288a11e6ded81", Archive: "tar.gz", Member: "mita"},
		},
		Build: &Build{Package: "github.com/enfein/mieru/v3/cmd/mita", Version: "v3.36.1"},
	},
	{
		// Surge's snell-server is closed source; the zips are Surge's official
		// downloads and the digests were computed from them on 2026-09-14.
		Core: "snell", Version: "5.0.0", Status: StatusCaution,
		Note: "Surge snell-server v5 (closed source); one shared PSK, no per-user accounting; not yet verified end to end",
		Assets: map[string]Asset{
			"linux/amd64": {URL: "https://dl.nssurge.com/snell/snell-server-v5.0.0-linux-amd64.zip", SHA256: "893a7be4fc5e695b97acb80af9a4a99b99867f8cb476784725a3f89fa23940e1", Archive: "zip", Member: "snell-server"},
			"linux/arm64": {URL: "https://dl.nssurge.com/snell/snell-server-v5.0.0-linux-aarch64.zip", SHA256: "76709032a8d1043fa6f01e1fbbb727148d77534a83293d73564a5692c3967292", Archive: "zip", Member: "snell-server"},
		},
	},
	{
		Core: "snell", Version: "4.1.1", Status: StatusCaution,
		Note: "Surge snell-server v4 for clients without v5 support",
		Assets: map[string]Asset{
			"linux/amd64": {URL: "https://dl.nssurge.com/snell/snell-server-v4.1.1-linux-amd64.zip", SHA256: "cc2271b79c7506888b34e651e8741b3aa7fc7d5f60aa65ef8bb096f3313a193b", Archive: "zip", Member: "snell-server"},
			"linux/arm64": {URL: "https://dl.nssurge.com/snell/snell-server-v4.1.1-linux-aarch64.zip", SHA256: "38d4cdc03dcdb3608af8594df83e1795265167fafc5d802f815148908902d758", Archive: "zip", Member: "snell-server"},
		},
	},
	{
		// zhboner/realm: the userspace relay the forward "realm" backend
		// runs. Digests computed from the GitHub release on 2026-09-15; the
		// musl builds serve Alpine.
		Core: "realm", Version: "2.9.6", Status: StatusCaution,
		Note: "zhboner/realm relay for the forward realm backend; not yet verified end to end",
		Assets: map[string]Asset{
			"linux/amd64":      {URL: "https://github.com/zhboner/realm/releases/download/v2.9.6/realm-x86_64-unknown-linux-gnu.tar.gz", SHA256: "b9efc8ccbab5c9f0602ab5ba0a2e00311e7b773944533a8373c00811fb6a1a6b", Archive: "tar.gz", Member: "realm"},
			"linux/arm64":      {URL: "https://github.com/zhboner/realm/releases/download/v2.9.6/realm-aarch64-unknown-linux-gnu.tar.gz", SHA256: "4b6c059df67a3161369df3133e5ea9e4bd266185c634ccc8990cd5bb8d271786", Archive: "tar.gz", Member: "realm"},
			"linux/amd64-musl": {URL: "https://github.com/zhboner/realm/releases/download/v2.9.6/realm-x86_64-unknown-linux-musl.tar.gz", SHA256: "b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65", Archive: "tar.gz", Member: "realm"},
			"linux/arm64-musl": {URL: "https://github.com/zhboner/realm/releases/download/v2.9.6/realm-aarch64-unknown-linux-musl.tar.gz", SHA256: "f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488", Archive: "tar.gz", Member: "realm"},
		},
	},
	{
		Core: "hysteria", Version: "2.12.2", Status: StatusTested,
		Note: "official Hysteria 2 server; verified with the official client, HTTP auth and traffic stats",
		Assets: map[string]Asset{
			"linux/amd64":  {URL: "https://github.com/apernet/hysteria/releases/download/app%2Fv2.12.2/hysteria-linux-amd64", SHA256: "6493dfffd55b5883f64c76c63880ecc32988f0c568c9ca9014907877b4d55f94", Archive: "raw"},
			"linux/arm64":  {URL: "https://github.com/apernet/hysteria/releases/download/app%2Fv2.12.2/hysteria-linux-arm64", SHA256: "ebfacc1ec3a0edfd742cd68ce17f292a6092e606b9d11f99b035c1d888f3d709", Archive: "raw"},
			"darwin/arm64": {URL: "https://github.com/apernet/hysteria/releases/download/app%2Fv2.12.2/hysteria-darwin-arm64", SHA256: "d5850b02d0952ab5f88cd9bf37d0e84585905aba107e3f977336f1047f107d9d", Archive: "raw"},
		},
	},
}

// Cores returns the core names present in the manifest, sorted.
func Cores() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range Manifest {
		if !seen[r.Core] {
			seen[r.Core] = true
			out = append(out, r.Core)
		}
	}
	sort.Strings(out)
	return out
}

// Releases returns the manifest entries for one core, newest first.
func Releases(core string) []Release {
	var out []Release
	for _, r := range Manifest {
		if r.Core == core {
			out = append(out, r)
		}
	}
	return out
}

// Find returns a specific release.
func Find(core, version string) (Release, bool) {
	for _, r := range Manifest {
		if r.Core == core && r.Version == version {
			return r, true
		}
	}
	return Release{}, false
}

// Tested returns the newest release marked tested for a core.
func Tested(core string) (Release, bool) {
	for _, r := range Manifest {
		if r.Core == core && r.Status == StatusTested {
			return r, true
		}
	}
	return Release{}, false
}

// Default returns the release to use when none is named: the newest tested
// one, or failing that the newest caution one. Broken releases are never
// chosen implicitly.
func Default(core string) (Release, bool) {
	if r, ok := Tested(core); ok {
		return r, true
	}
	for _, r := range Manifest {
		if r.Core == core && r.Status == StatusCaution {
			return r, true
		}
	}
	return Release{}, false
}
