#include "core/InstanceSecret.h"

#include "core/Logger.h"
#include "store/SqliteStore.h"

#include <openssl/rand.h>

#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace bsfchat {
namespace {

// The server_meta key. Deliberately generic: it is a SERVER instance secret,
// not any one subsystem's. See the header.
constexpr char kInstanceSecretMetaKey[] = "server.instance_secret";

// 32 bytes, rendered as hex. Hex rather than raw bytes because server_meta.value
// is TEXT and a random byte string is not valid UTF-8.
constexpr size_t kSecretBytes = 32;

// Anything shorter than this in the row is treated as absent and regenerated.
// It cannot happen from this code path; it is the guard against a hand-edited
// or truncated row silently weakening every key on the server.
constexpr size_t kMinSecretChars = 32;

std::mutex& generate_mutex() {
    static std::mutex m;
    return m;
}

} // namespace

std::string get_or_create_instance_secret(SqliteStore& store) {
    // Fast path: no lock, one indexed lookup. Callers cache the DERIVED key
    // anyway (std::call_once in MediaHandler and SyncEngine), so in a running
    // server this runs once per subsystem per process.
    if (auto existing = store.get_meta(kInstanceSecretMetaKey);
        existing && existing->size() >= kMinSecretChars) {
        return *existing;
    }

    std::lock_guard lock(generate_mutex());

    // Re-read under the lock. Without this, two subsystems reaching the fast
    // path together would both generate, both write, and the one that lost the
    // race would hold keys derived from a secret no longer in the database —
    // so every ticket and every sync token it had already issued would stop
    // verifying.
    if (auto existing = store.get_meta(kInstanceSecretMetaKey);
        existing && existing->size() >= kMinSecretChars) {
        return *existing;
    }

    unsigned char buf[kSecretBytes];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        throw std::runtime_error(
            "instance secret: RAND_bytes failed generating the server instance secret");
    }
    std::ostringstream oss;
    for (unsigned char b : buf) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    const std::string secret = oss.str();
    store.set_meta(kInstanceSecretMetaKey, secret);
    get_logger()->info("Generated this server's instance secret (media tickets and sync "
                       "tokens are signed with keys derived from it)");
    return secret;
}

} // namespace bsfchat
