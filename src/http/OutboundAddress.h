#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bsfchat::outbound {

// Address classification for requests the server makes on a USER's behalf
// (URL previews; see docs/url-previews.md).
//
// The rule is about where the bytes go, not what the URL says: these functions
// take addresses the resolver actually returned, so every spelling of a
// hostile host — "0x7f.1", "[::ffff:127.0.0.1]", a public name whose A record
// is 10.0.0.5 — is judged by the address it reaches. The caller then connects
// to that same address (never re-resolving), so DNS rebinding between the
// check and the connect cannot swap it.
//
// Push delivery has its own, older literal-host check in api/PushHandler.cpp
// (the operator allowlist is that path's real gate). This one is deliberately
// stricter: it refuses everything that is not ordinary global unicast.

// One resolved address, family-tagged. IPv4 is held in the first four bytes
// of `bytes`, network order.
struct IpAddress {
    bool v6 = false;
    std::array<uint8_t, 16> bytes{};

    static IpAddress from_v4(uint32_t host_order);
    // Numeric literal only (inet_pton; dotted-quad IPv4 or IPv6, no brackets).
    static std::optional<IpAddress> parse(const std::string& literal);
    std::string to_string() const;
};

struct Cidr {
    IpAddress base;
    int prefix = 0;
    bool contains(const IpAddress& a) const;
};

// "10.0.0.0/8", "2001:db8::/32", or a bare address (a /32 or /128).
std::optional<Cidr> parse_cidr(const std::string& text);

// Why an address was refused, or nullptr when it is ordinary global unicast.
// Covers: 0/8, loopback, RFC1918, CGNAT 100.64/10, link-local 169.254/16 (cloud
// metadata), IETF/documentation/benchmark ranges, multicast, 240/4 and
// broadcast; IPv6 ::, ::1, fc00::/7, fe80::/10, fec0::/10, ff00::/8, the
// IPv4-mapped/compatible ::/96 and ::ffff:0:0/96, NAT64 64:ff9b::/96 and
// 64:ff9b:1::/48, Teredo 2001::/32, documentation 2001:db8::/32, discard
// 100::/64, and 6to4 2002::/16 whose embedded IPv4 is itself refused.
const char* builtin_refusal(const IpAddress& a);

// builtin_refusal() plus an operator denylist.
const char* refusal(const IpAddress& a, const std::vector<Cidr>& extra_denylist);

} // namespace bsfchat::outbound
