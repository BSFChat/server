#pragma once

#include <string>

namespace bsfchat {

class SqliteStore;

// This deployment's own secret, as 64 lowercase hex characters (32 bytes of
// CSPRNG output), generated on first use and kept in `server_meta` under
// `server.instance_secret`.
//
// WHAT IT IS FOR. Nothing signs or encrypts with this value directly. It is the
// input keying material every subsystem that needs a server-held key derives
// from, each under its own HKDF salt:
//
//     media tickets   HKDF(ikm = this, salt = "bsfchat/media-ticket/v1", ...)
//     sync tokens     HKDF(ikm = this, salt = "bsfchat/sync-token/v1",   ...)
//
// A new subsystem adds a salt; it never reuses another subsystem's derived key
// and never uses the secret raw. The salts are what guarantee that recovering
// one derived key — or confusing a value signed under one for a value signed
// under another — tells an attacker nothing about the rest.
//
// WHY IT LIVES HERE RATHER THAN IN CONFIG. An operator-set secret is one more
// thing to generate, distribute and forget, and one more "everything stopped
// working after the redeploy" support call. A process-local random key would
// invalidate every outstanding ticket and force every client on the deployment
// into a full initial sync on every restart. This is generated once, by the
// server, for itself, and survives a restart because it is a row.
//
// WHY NOT A MIGRATION. `server_meta` has existed since v1, so this needs no
// schema change at all — and a migration that writes a secret puts that secret
// into every operator's backup of the migration step, which is worse.
//
// CONCURRENCY. Two subsystems asking for the secret for the first time at the
// same moment must not each generate one and race to store it: the loser's
// derived keys would then verify nothing. This serialises on its own mutex and
// re-reads the row under it, so exactly one value is ever written per database.
// (One process, one database — the SQLite store is not shared between servers —
// so there is no other writer to coordinate with.)
//
// Throws std::runtime_error if the CSPRNG fails. A server that cannot produce
// 256 secure bits must not start signing things with predictable ones.
std::string get_or_create_instance_secret(SqliteStore& store);

} // namespace bsfchat
