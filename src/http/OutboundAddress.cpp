#include "http/OutboundAddress.h"

#include <arpa/inet.h>

#include <cstring>

namespace bsfchat::outbound {

IpAddress IpAddress::from_v4(uint32_t host_order) {
    IpAddress a;
    a.bytes[0] = static_cast<uint8_t>(host_order >> 24);
    a.bytes[1] = static_cast<uint8_t>(host_order >> 16);
    a.bytes[2] = static_cast<uint8_t>(host_order >> 8);
    a.bytes[3] = static_cast<uint8_t>(host_order);
    return a;
}

std::optional<IpAddress> IpAddress::parse(const std::string& literal) {
    IpAddress a;
    in_addr v4{};
    if (inet_pton(AF_INET, literal.c_str(), &v4) == 1) {
        std::memcpy(a.bytes.data(), &v4, 4);
        return a;
    }
    in6_addr v6{};
    if (inet_pton(AF_INET6, literal.c_str(), &v6) == 1) {
        a.v6 = true;
        std::memcpy(a.bytes.data(), &v6, 16);
        return a;
    }
    return std::nullopt;
}

std::string IpAddress::to_string() const {
    char buf[INET6_ADDRSTRLEN] = {};
    if (!inet_ntop(v6 ? AF_INET6 : AF_INET, bytes.data(), buf, sizeof(buf))) return {};
    return buf;
}

bool Cidr::contains(const IpAddress& a) const {
    if (a.v6 != base.v6) return false;
    int bits = prefix;
    for (std::size_t i = 0; bits > 0; ++i, bits -= 8) {
        const uint8_t mask = bits >= 8 ? 0xff : static_cast<uint8_t>(0xff << (8 - bits));
        if ((a.bytes[i] & mask) != (base.bytes[i] & mask)) return false;
    }
    return true;
}

std::optional<Cidr> parse_cidr(const std::string& text) {
    const auto slash = text.find('/');
    auto addr = IpAddress::parse(text.substr(0, slash));
    if (!addr) return std::nullopt;
    const int max = addr->v6 ? 128 : 32;
    int prefix = max;
    if (slash != std::string::npos) {
        const std::string p = text.substr(slash + 1);
        if (p.empty() || p.size() > 3 || p.find_first_not_of("0123456789") != std::string::npos)
            return std::nullopt;
        prefix = std::stoi(p);
        if (prefix > max) return std::nullopt;
    }
    return Cidr{*addr, prefix};
}

namespace {

uint32_t v4_of(const uint8_t* b) {
    return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
           (static_cast<uint32_t>(b[2]) << 8) | b[3];
}

bool in4(uint32_t addr, uint32_t net, int prefix) {
    const uint32_t mask = prefix == 0 ? 0 : 0xffffffffu << (32 - prefix);
    return (addr & mask) == (net & mask);
}

constexpr uint32_t ip4(unsigned a, unsigned b, unsigned c, unsigned d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const char* v4_refusal(uint32_t a) {
    if (in4(a, ip4(0, 0, 0, 0), 8)) return "this-network (0.0.0.0/8)";
    if (in4(a, ip4(10, 0, 0, 0), 8)) return "private (10.0.0.0/8)";
    if (in4(a, ip4(100, 64, 0, 0), 10)) return "carrier-grade NAT (100.64.0.0/10)";
    if (in4(a, ip4(127, 0, 0, 0), 8)) return "loopback (127.0.0.0/8)";
    if (in4(a, ip4(169, 254, 0, 0), 16)) return "link-local / cloud metadata (169.254.0.0/16)";
    if (in4(a, ip4(172, 16, 0, 0), 12)) return "private (172.16.0.0/12)";
    if (in4(a, ip4(192, 0, 0, 0), 24)) return "IETF protocol assignments (192.0.0.0/24)";
    if (in4(a, ip4(192, 0, 2, 0), 24)) return "documentation (192.0.2.0/24)";
    if (in4(a, ip4(192, 88, 99, 0), 24)) return "6to4 relay anycast (192.88.99.0/24)";
    if (in4(a, ip4(192, 168, 0, 0), 16)) return "private (192.168.0.0/16)";
    if (in4(a, ip4(198, 18, 0, 0), 15)) return "benchmarking (198.18.0.0/15)";
    if (in4(a, ip4(198, 51, 100, 0), 24)) return "documentation (198.51.100.0/24)";
    if (in4(a, ip4(203, 0, 113, 0), 24)) return "documentation (203.0.113.0/24)";
    if (in4(a, ip4(224, 0, 0, 0), 4)) return "multicast (224.0.0.0/4)";
    if (in4(a, ip4(240, 0, 0, 0), 4)) return "reserved / broadcast (240.0.0.0/4)";
    return nullptr;
}

} // namespace

const char* builtin_refusal(const IpAddress& a) {
    if (!a.v6) return v4_refusal(v4_of(a.bytes.data()));

    const uint8_t* b = a.bytes.data();
    auto zero = [&](int from, int to) {
        for (int i = from; i < to; ++i)
            if (b[i] != 0) return false;
        return true;
    };

    // ::/96 holds ::, ::1 and the deprecated IPv4-compatible form; nothing in
    // it is a public IPv6 host.
    if (zero(0, 12)) {
        if (zero(12, 15) && b[15] == 0) return "unspecified (::)";
        if (zero(12, 15) && b[15] == 1) return "loopback (::1)";
        return "IPv4-compatible (::/96)";
    }
    // Mapped: a dual-stack socket connecting here reaches IPv4. Refused
    // whether or not the embedded address is public — no real AAAA record
    // points at one, and judging the embedded half is where filters slip.
    if (zero(0, 10) && b[10] == 0xff && b[11] == 0xff) return "IPv4-mapped (::ffff:0:0/96)";
    // NAT64: reaches arbitrary IPv4, including private, via the translator.
    if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b) {
        if (zero(4, 12)) return "NAT64 (64:ff9b::/96)";
        if (b[4] == 0x00 && b[5] == 0x01) return "local NAT64 (64:ff9b:1::/48)";
    }
    if (b[0] == 0x01 && b[1] == 0x00 && zero(2, 8)) return "discard-only (100::/64)";
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) return "Teredo (2001::/32)";
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
        return "documentation (2001:db8::/32)";
    if (b[0] == 0x20 && b[1] == 0x02) {
        // 6to4 embeds an IPv4 address in bits 16..47.
        if (v4_refusal(v4_of(b + 2))) return "6to4 wrapping a refused IPv4";
    }
    if ((b[0] & 0xfe) == 0xfc) return "unique local (fc00::/7)";
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return "link-local (fe80::/10)";
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0) return "site-local (fec0::/10)";
    if (b[0] == 0xff) return "multicast (ff00::/8)";
    return nullptr;
}

const char* refusal(const IpAddress& a, const std::vector<Cidr>& extra_denylist) {
    if (const char* r = builtin_refusal(a)) return r;
    for (const auto& c : extra_denylist) {
        if (c.contains(a)) return "operator denylist";
    }
    return nullptr;
}

} // namespace bsfchat::outbound
