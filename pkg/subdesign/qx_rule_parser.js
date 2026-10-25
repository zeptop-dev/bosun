// Copyright Zeptop. Licensed under the MIT license.
// Quantumult X resource parser API: crossutility/Quantumult-X/resource-parser.js.
// Only designer rule resources enable this parser. It never handles credentials.
(function () {
  "use strict";
  try {
    var source = $resource.content;
    if (typeof source !== "string" || source.length > 8 * 1024 * 1024) {
      throw new Error("Rule resource is missing or too large");
    }
    var lines = source.replace(/^\uFEFF/, "").split(/\r?\n/);
    if (lines.length > 200000) throw new Error("Too many rules");
    var output = [
      "# ACL4SSR rule adaptation by Captain; source: https://github.com/ACL4SSR/ACL4SSR",
      "# ACL4SSR data license: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/"
    ];
    var kinds = {
      "DOMAIN": "host", "DOMAIN-SUFFIX": "host-suffix", "DOMAIN-KEYWORD": "host-keyword",
      "IP-CIDR": "ip-cidr", "IP-CIDR6": "ip6-cidr", "GEOIP": "geoip"
    };
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || /^(#|;|\/\/)/.test(line)) continue;
      var parts = line.split(",").map(function (x) { return x.trim(); });
      var kind = parts[0].toUpperCase();
      var value = parts[1] || "";
      var ip = kind === "IP-CIDR" || kind === "IP-CIDR6" || kind === "GEOIP";
      if (!Object.prototype.hasOwnProperty.call(kinds, kind) || parts.length < 2 || parts.length > 3 ||
          (parts.length === 3 && (!ip || parts[2] !== "no-resolve")) || !value ||
          /[\s\x00-\x1f\x7f\u2028\u2029]/.test(value)) {
        throw new Error("Unsupported rule or option on line " + (i + 1));
      }
      if ((kind === "DOMAIN" || kind === "DOMAIN-SUFFIX") &&
          (!/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/.test(value) || value.length > 253)) {
        throw new Error("Invalid domain on line " + (i + 1));
      }
      if (kind === "DOMAIN-KEYWORD" && !/^[a-zA-Z0-9_.-]+$/.test(value)) {
        throw new Error("Unsupported domain keyword on line " + (i + 1));
      }
      if (kind === "GEOIP" && !/^[A-Z]{2}$/i.test(value)) {
        throw new Error("Unsupported GeoIP code on line " + (i + 1));
      }
      if (kind === "IP-CIDR" || kind === "IP-CIDR6") {
        var cidr = value.split("/");
        var maximum = kind === "IP-CIDR6" ? 128 : 32;
        if (cidr.length !== 2 || !/^\d{1,3}$/.test(cidr[1]) || Number(cidr[1]) > maximum) {
          throw new Error("Invalid IP prefix on line " + (i + 1));
        }
        if (kind === "IP-CIDR") {
          var octets = cidr[0].split(".");
          if (octets.length !== 4 || octets.some(function (x) { return !/^\d{1,3}$/.test(x) || Number(x) > 255; })) {
            throw new Error("Invalid IPv4 prefix on line " + (i + 1));
          }
        } else if (!/^[0-9a-f:.]+$/i.test(cidr[0]) || cidr[0].indexOf(":") < 0) {
          throw new Error("Invalid IPv6 prefix on line " + (i + 1));
        }
      }
      // The resource's force-policy supplies the real policy. REJECT is an
      // intentionally safe default if this resource is imported without it.
      output.push(kinds[kind] + "," + value + ",reject" + (parts.length === 3 ? ",no-resolve" : ""));
    }
    $done({ content: output.join("\n") + "\n" });
  } catch (error) {
    // No partial content: Quantumult X must retain/fail the whole resource,
    // rather than accepting a shortened list with different routing behavior.
    $done({ error: "Captain rule conversion failed: " + error.message });
  }
}());
