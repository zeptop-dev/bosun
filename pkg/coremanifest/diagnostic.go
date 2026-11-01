package coremanifest

// DiagnosticRelease is the pinned optional geocheck helper. It is not a
// selectable proxy core, but uses the same authenticated artifact delivery.
func DiagnosticRelease() Release {
	base := RegistryBase + "v0.57.0/"
	assets := map[string]Asset{}
	for _, arch := range []string{"amd64", "arm64"} {
		assets["linux/"+arch] = Asset{URL: base + "geocheck-linux-" + arch, SumsURL: base + "SHA256SUMS", Archive: "raw"}
	}
	return Release{Core: "geocheck", Version: "0.3.0-r1", Assets: assets}
}

// RouteToolRelease describes the optional upstream NextTrace executable. Its
// GPL source is neither copied into nor linked with bosun; distribution stays
// a separate, fixed upstream artifact with its reviewed checksum.
func RouteToolRelease() Release {
	return Release{Core: "nexttrace", Version: "v1.7.4", Assets: map[string]Asset{
		"linux/amd64": {URL: "https://github.com/nxtrace/NTrace-core/releases/download/v1.7.4/nexttrace-tiny_linux_amd64", SHA256: "68b6a2210724a4b9439d9337ac69bf17fc7d662002a9a9dbdc5b96c1ab44ca26", Archive: "raw"},
		"linux/arm64": {URL: "https://github.com/nxtrace/NTrace-core/releases/download/v1.7.4/nexttrace-tiny_linux_arm64", SHA256: "ce8fb581c2bd30a157aec4a38e5c0fa1c79eac3b761a978146267b6ae1c678e3", Archive: "raw"},
	}}
}
