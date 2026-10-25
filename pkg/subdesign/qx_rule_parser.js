// Copyright Zeptop. Licensed under the MIT license.
// Quantumult X resource parser API: crossutility/Quantumult-X/resource-parser.js.
// Only designer rule resources enable this parser. It never handles credentials.
(function () {
  "use strict";
  function ipv4(address) {
    var octets = address.split(".");
    return octets.length === 4 && octets.every(function (x) {
      return /^(0|[1-9][0-9]{0,2})$/.test(x) && Number(x) <= 255;
    });
  }
  function ipv6(address) {
    // An embedded IPv4 tail occupies two of the eight 16-bit groups.
    if (address.indexOf(".") >= 0) {
      var separator = address.lastIndexOf(":");
      if (separator < 0 || !ipv4(address.slice(separator + 1))) return false;
      address = address.slice(0, separator + 1) + "0:0";
    }
    var compression = address.indexOf("::");
    var groups;
    if (compression >= 0) {
      if (compression !== address.lastIndexOf("::")) return false;
      var left = address.slice(0, compression);
      var right = address.slice(compression + 2);
      groups = (left ? left.split(":") : []).concat(right ? right.split(":") : []);
      if (groups.length >= 8) return false; // :: must replace at least one group.
    } else {
      groups = address.split(":");
      if (groups.length !== 8) return false;
    }
    return groups.every(function (x) { return /^[0-9a-f]{1,4}$/i.test(x); });
  }
  function domain(value) {
    if (value.length === 0 || value.length > 253) return false;
    return value.split(".").every(function (label) {
      // DNS service labels such as _ldap._tcp are valid. Empty labels,
      // hyphens at label boundaries and oversized labels are not.
      return label.length > 0 && label.length <= 63 &&
        /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/.test(label) && label.slice(-1) !== "-";
    });
  }
  try {
    var source = $resource.content;
    if (typeof source !== "string" || source.length > 8 * 1024 * 1024) {
      throw new Error("Rule resource is missing or too large");
    }
    var lines = source.replace(/^\uFEFF/, "").split(/\r?\n/);
    if (lines.length > 200000) throw new Error("Too many rules");
    var output = ["# Rule adaptation by Captain"];
    if (typeof $resource.link === "string" && /^https:\/\/raw\.githubusercontent\.com\/ACL4SSR\/ACL4SSR\//.test($resource.link)) {
      output.push("# Source: https://github.com/ACL4SSR/ACL4SSR");
      output.push("# ACL4SSR data license: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/");
    }
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
      if (kind === "DOMAIN" || kind === "DOMAIN-SUFFIX") {
        // A single final DNS root dot does not change the matched hostname.
        if (value.slice(-1) === ".") value = value.slice(0, -1);
        if (!domain(value)) throw new Error("Invalid domain on line " + (i + 1));
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
        if (cidr.length !== 2 || !/^(0|[1-9][0-9]{0,2})$/.test(cidr[1]) || Number(cidr[1]) > maximum) {
          throw new Error("Invalid IP prefix on line " + (i + 1));
        }
        if (kind === "IP-CIDR") {
          if (!ipv4(cidr[0])) {
            throw new Error("Invalid IPv4 prefix on line " + (i + 1));
          }
        } else if (!ipv6(cidr[0])) {
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
