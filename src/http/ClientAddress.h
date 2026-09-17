#pragma once

#include <httplib.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bsfchat {

// An IPv4 or IPv6 network in CIDR form. IPv4 is held as an IPv4-mapped IPv6
// address so one comparison path serves both families, and so a dual-stack
// listener reporting "::ffff:10.0.0.1" matches a "10.0.0.0/8" entry.
struct IpNetwork {
    std::array<uint8_t, 16> addr{};
    int prefix_bits = 128; // always in IPv6 terms (IPv4 /n is stored as 96 + n)

    // Accepts "10.0.0.0/8", "192.168.1.1", "fd00::/8", "::1". Returns nullopt
    // for anything else, including a prefix length out of range for the family.
    static std::optional<IpNetwork> parse(const std::string& cidr);

    [[nodiscard]] bool contains(const std::array<uint8_t, 16>& ip) const;
};

// Works out which address a request should be attributed to for rate limiting.
//
// This server is documented as running behind a reverse proxy, where the
// socket peer is the PROXY for every request. Keying a limiter on that would
// put the entire internet in one bucket: the first person to trip it locks
// everybody out, which is a worse outage than the attack being limited. So
// the peer address is only believed when the peer is not a known proxy, and
// X-Forwarded-For is only believed when the peer IS one — otherwise any
// client could mint itself a fresh identity per request by sending the header.
class ClientAddressResolver {
public:
    // Throws std::invalid_argument naming the offending entry if one does not
    // parse. A typo here must not be silently dropped: the entry it was meant
    // to add is the difference between per-client limits and one shared bucket.
    explicit ClientAddressResolver(const std::vector<std::string>& trusted_proxies);

    // The client's address in canonical form, with IPv6 collapsed to its /64
    // (a single subscriber routinely controls a whole /64, so per-address
    // limits would be no limit at all) — or nullopt when the client cannot be
    // told apart from other clients:
    //
    //   * the peer is a trusted proxy but sent no usable X-Forwarded-For, or
    //     every hop in it is itself a trusted proxy;
    //   * the peer address is missing or unparseable.
    //
    // Callers must treat nullopt as "skip per-address limits", never as a
    // shared bucket.
    [[nodiscard]] std::optional<std::string> resolve(const httplib::Request& req) const;

    // True when the request looks like it came through a reverse proxy that is
    // NOT in the trusted list: a private or loopback peer that nevertheless
    // supplied X-Forwarded-For. Every client of such a deployment shares the
    // proxy's bucket until the operator lists it; callers use this to say so
    // in the log.
    [[nodiscard]] bool looks_like_untrusted_proxy(const httplib::Request& req) const;

private:
    [[nodiscard]] bool is_trusted(const std::array<uint8_t, 16>& ip) const;

    std::vector<IpNetwork> trusted_;
};

} // namespace bsfchat
