#include "http/ClientAddress.h"

// httplib.h (via the header above) has already pulled in the platform socket
// headers, so inet_pton/inet_ntop are declared on every platform it supports.

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace bsfchat {

namespace {

using Bytes16 = std::array<uint8_t, 16>;

constexpr int kV4Offset = 96; // bits of ::ffff:0:0/96 in front of a mapped IPv4

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

bool is_v4_mapped(const Bytes16& ip) {
    static constexpr uint8_t kPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return std::memcmp(ip.data(), kPrefix, sizeof(kPrefix)) == 0;
}

// Parses a bare address into IPv4-mapped-or-native IPv6 bytes. Tolerates the
// decorations that turn up in X-Forwarded-For: "[v6]", "[v6]:port",
// "v4:port", and a "%zone" suffix.
std::optional<Bytes16> parse_ip(std::string s) {
    s = trim(s);
    if (s.empty() || s.size() > 64) return std::nullopt;

    if (s.front() == '[') {
        const auto close = s.find(']');
        if (close == std::string::npos) return std::nullopt;
        s = s.substr(1, close - 1);
    } else if (std::count(s.begin(), s.end(), ':') == 1 && s.find('.') != std::string::npos) {
        s.resize(s.find(':'));
    }
    if (const auto zone = s.find('%'); zone != std::string::npos) s.resize(zone);

    Bytes16 out{};
    uint8_t v4[4];
    if (inet_pton(AF_INET, s.c_str(), v4) == 1) {
        out[10] = out[11] = 0xff;
        std::memcpy(out.data() + 12, v4, 4);
        return out;
    }
    if (inet_pton(AF_INET6, s.c_str(), out.data()) == 1) return out;
    return std::nullopt;
}

bool in_any(const Bytes16& ip, std::initializer_list<const char*> cidrs) {
    for (const char* c : cidrs) {
        if (IpNetwork::parse(c)->contains(ip)) return true;
    }
    return false;
}

std::string canonical(Bytes16 ip) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (is_v4_mapped(ip)) {
        inet_ntop(AF_INET, ip.data() + 12, buf, sizeof(buf));
        return buf;
    }
    std::fill(ip.begin() + 8, ip.end(), uint8_t{0});
    inet_ntop(AF_INET6, ip.data(), buf, sizeof(buf));
    return std::string(buf) + "/64";
}

} // namespace

std::optional<IpNetwork> IpNetwork::parse(const std::string& cidr) {
    const auto slash = cidr.find('/');
    auto ip = parse_ip(cidr.substr(0, slash));
    if (!ip) return std::nullopt;

    const bool v4 = is_v4_mapped(*ip);
    IpNetwork net;
    net.addr = *ip;
    if (slash == std::string::npos) return net;

    const auto len = trim(cidr.substr(slash + 1));
    if (len.empty() || len.size() > 3 ||
        !std::all_of(len.begin(), len.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
    }
    const int bits = std::stoi(len);
    if (bits > (v4 ? 32 : 128)) return std::nullopt;
    net.prefix_bits = v4 ? kV4Offset + bits : bits;
    return net;
}

bool IpNetwork::contains(const Bytes16& ip) const {
    const int full = prefix_bits / 8;
    if (std::memcmp(addr.data(), ip.data(), static_cast<size_t>(full)) != 0) return false;
    const int rest = prefix_bits % 8;
    if (rest == 0) return true;
    const auto mask = static_cast<uint8_t>(0xff << (8 - rest));
    return (addr[full] & mask) == (ip[full] & mask);
}

bool is_private_or_loopback_network(const IpNetwork& net) {
    // A shorter prefix means a WIDER network, so a candidate is only fully
    // contained when the private range's prefix is no longer than its own and
    // its base address falls inside. Checking containment of the base address
    // alone would accept 0.0.0.0/0, whose base 0.0.0.0 is in no private range
    // but whose membership is everything.
    static const char* kPrivate[] = {
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    };
    for (const char* cidr : kPrivate) {
        const auto range = IpNetwork::parse(cidr);
        if (!range) continue;
        if (range->prefix_bits <= net.prefix_bits && range->contains(net.addr)) return true;
    }
    return false;
}

ClientAddressResolver::ClientAddressResolver(const std::vector<std::string>& trusted_proxies) {
    for (const auto& entry : trusted_proxies) {
        auto net = IpNetwork::parse(entry);
        if (!net) {
            throw std::invalid_argument("'" + entry + "' is not an IP address or CIDR network");
        }
        trusted_.push_back(*net);
    }
}

bool ClientAddressResolver::is_trusted(const Bytes16& ip) const {
    return std::any_of(trusted_.begin(), trusted_.end(),
                       [&](const IpNetwork& n) { return n.contains(ip); });
}

std::optional<std::string> ClientAddressResolver::resolve(const httplib::Request& req) const {
    auto peer = parse_ip(req.remote_addr);
    if (!peer) return std::nullopt;
    if (!is_trusted(*peer)) return canonical(*peer);

    // The peer is a proxy we trust, so its X-Forwarded-For is worth reading.
    //
    // ...provided it arrives as ONE line. HTTP says repeated lines concatenate
    // in order, but httplib keeps headers in a std::unordered_multimap, which
    // makes no promise about the relative order of equal keys — libc++ happens
    // to preserve it, libstdc++ does not (this failed on the Linux CI only).
    // With the order unknowable, "rightmost" is unknowable too, and guessing
    // wrong hands the client the choice of its own rate-limit identity: send
    // your own X-Forwarded-For, and a proxy that ADDS a line rather than
    // appending puts your invented value where the vouched-for one should be.
    // So more than one line means we do not know who this is. nginx and every
    // mainstream proxy fold the header into a single line, so this only bites
    // a proxy that was already behaving unusually.
    std::vector<std::string> hops;
    const auto lines = req.get_header_value_count("X-Forwarded-For");
    if (lines > 1) return std::nullopt;
    for (size_t i = 0; i < lines; ++i) {
        const auto line = req.get_header_value("X-Forwarded-For", "", i);
        size_t start = 0;
        while (start <= line.size()) {
            const auto comma = line.find(',', start);
            const auto end = comma == std::string::npos ? line.size() : comma;
            hops.push_back(line.substr(start, end - start));
            start = end + 1;
        }
    }

    // Walk from the RIGHT. Each proxy appends the address it saw, so the
    // rightmost entry is the only one our trusted peer vouches for, and
    // everything to the left of the first untrusted hop was supplied by that
    // hop and may be invented. Taking the leftmost entry — the usual mistake —
    // hands the client the choice of its own rate-limit identity.
    for (auto it = hops.rbegin(); it != hops.rend(); ++it) {
        auto hop = parse_ip(*it);
        // "unknown" or an obfuscated node id (RFC 7239): a trusted proxy is
        // telling us it does not know. Neither do we.
        if (!hop) return std::nullopt;
        if (!is_trusted(*hop)) return canonical(*hop);
    }
    return std::nullopt;
}

bool ClientAddressResolver::looks_like_untrusted_proxy(const httplib::Request& req) const {
    if (!req.has_header("X-Forwarded-For")) return false;
    auto peer = parse_ip(req.remote_addr);
    if (!peer || is_trusted(*peer)) return false;
    return in_any(*peer, {"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                          "::1", "fc00::/7"});
}

} // namespace bsfchat
