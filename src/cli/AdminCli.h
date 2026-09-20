#pragma once

#include <functional>
#include <iosfwd>
#include <string>
#include <vector>

namespace bsfchat {

// Offline administration for whoever controls the host.
//
// ── The incident this exists for ─────────────────────────────────────────
//
// bootstrap_roles gives the `admin` role to the OLDEST account by created_at
// and @everyone to everybody else, once, and never revisits the decision. On
// the production deployment the owner's original password account held admin;
// he then started signing in through the identity provider, which minted a
// SECOND account (`@oidc_<sub>:...`, see the m.login.token path in
// AuthHandler) that got @everyone only. Granting a role requires MANAGE_ROLES,
// the only account holding it had no live session, and so the Server Settings
// gear was unreachable from every client he was actually signed in to. There
// was no supported way out: the recovery was hand-written INSERTs into
// `server_state` and `events` over SSH.
//
// Those hand-written rows are the reason this file exists rather than a
// runbook. They skipped all three things a role write is supposed to do —
// the authoritative `server_state` row was written without the audit record,
// without the /sync mirror event, and with a stream position picked by hand.
// Clients did not learn about the grant until they were restarted, and the
// audit log has no record that the most powerful role on the server changed
// hands. Every command here goes through write_server_scoped_state, which is
// the one choke point that does all three.
//
// ── Why this is not a privilege-escalation path ──────────────────────────
//
// It grants nothing to anyone who could not already take it. Running a command
// here requires the ability to execute the server binary AND read the config
// file AND write the SQLite database — which is to say, the operator account
// the server itself runs as. Anybody holding that can already open the
// database with `sqlite3` and write whatever they like; that is exactly what
// happened on production. Nothing here is reachable over HTTP, no subcommand
// opens a socket to serve on, and no token, password or session is created.
// The capability is unchanged. What changes is that using it now produces a
// correct, audited, client-visible write instead of three rows that looked
// right.
//
// ── Why the server has to be stopped ─────────────────────────────────────
//
// Not for secrecy — for correctness, and the failure is nasty. SqliteStore
// holds the stream-position head in memory (next_stream_position_, loaded once
// in initialize() and handed out by claim_stream_position_locked). A second
// process opening the same database reads the same head and claims positions
// from it. The mirror event this tool writes would therefore take a position
// the RUNNING server still believes is free, and the running server's next
// event insert would hit the UNIQUE constraint on events.stream_position —
// i.e. the next message anyone sends throws, in the server, long after the
// admin command exited successfully. SQLite's own locking does not prevent
// this: both processes are legitimate writers, they simply disagree about a
// counter neither reads back.
//
// The in-process SyncEngine is the smaller half of the same problem: a live
// server would not call notify_new_event for a write made behind its back, so
// connected clients would sit on the old role set until their next full sync.
//
// So every command below refuses to run while something is listening on the
// configured address and port (see listen_probe). That check is best-effort by
// construction — a server inside a container has its own network namespace, so
// run the command in the SAME namespace as the server (`docker compose exec`
// against the stopped service, or `docker compose run --rm`) and not on the
// host. The check catches the ordinary systemd/bare-metal mistake, which is
// the one an operator actually makes at 2am.

// "Is something already listening on (address, port)?"
//
// A seam rather than a detail so the refusal path can be tested without
// binding real ports and without a real server; tests pass their own.
using ListenProbe = std::function<bool(const std::string& address, int port)>;

// The real probe: tries to bind the address, and reports "in use" only when the
// kernel says so. Deliberately sets no SO_REUSEADDR/SO_REUSEPORT — the whole
// point is to fail the way a second server would.
bool default_listen_probe(const std::string& address, int port);

// True when `token` names a subcommand handled here, i.e. when main() should
// hand the arguments over instead of starting a server.
bool is_admin_subcommand(const std::string& token);

// Runs one subcommand. `args` starts WITH the subcommand name, so
// {"grant-admin", "--config", "...", "--user", "@josh:example.org"}.
//
// Returns the process exit code: 0 on success, 2 on a usage error, 1 on a
// refusal or a failure that is not the caller's syntax. Everything a human
// needs to read goes to `out`; nothing is written to the database unless the
// command succeeds.
int run_admin_cli(const std::vector<std::string>& args, std::ostream& out,
                  ListenProbe probe = default_listen_probe);

// The usage block, also printed by `bsfchat-server --help`.
void print_admin_usage(std::ostream& out);

} // namespace bsfchat
