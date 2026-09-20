#include "cli/AdminCli.h"

#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "store/SqliteStore.h"

#include <bsfchat/Constants.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <ostream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace bsfchat {

namespace {

// Parsed form of the options every subcommand shares.
struct CommonArgs {
    std::string config_path;
    std::string user_id;
    bool ok = false;
    std::string error;  // set when ok is false
};

// Strict, and it refuses rather than guessing, for the same reason main()'s
// argument loop does: this tool writes to a database, and a typo that makes it
// write to a DIFFERENT database is precisely the accident the rest of this
// project has already had twice.
//
// --config is REQUIRED here, unlike on the server path where omitting it falls
// back to built-in defaults. Those defaults put the database at a RELATIVE
// ./data/bsfchat.db, so an operator running `bsfchat-server grant-admin --user
// @me:example.org` from their home directory would silently create an empty
// database, grant admin in it, and print success. The server can afford that
// default because a wrong database there is loud within seconds; a one-shot
// command that exits 0 is not.
CommonArgs parse_common(const std::vector<std::string>& args, bool wants_user) {
    CommonArgs out;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "--config") {
            if (i + 1 >= args.size()) { out.error = "--config requires a path"; return out; }
            out.config_path = args[++i];
        } else if (arg == "--user") {
            if (i + 1 >= args.size()) { out.error = "--user requires a user id"; return out; }
            out.user_id = args[++i];
        } else {
            out.error = "unrecognised argument: " + log_safe(arg);
            return out;
        }
    }
    if (out.config_path.empty()) {
        out.error = "--config is required; this command will not guess which database to write to";
        return out;
    }
    if (wants_user && out.user_id.empty()) {
        out.error = "--user is required";
        return out;
    }
    out.ok = true;
    return out;
}

// The synthetic actor recorded as having made the change.
//
// NOT @server:<name>, which is what bootstrap_roles writes under. The
// difference is the whole point of recording it: "the server granted the first
// account Admin at bootstrap" and "somebody with shell access on the host
// granted this account Admin" are different events, and an owner asking six
// months later how an account got admin needs the log to tell them apart.
//
// `console` is reserved in handle_register, alongside `server`, so no real
// account can ever share this id and blur the distinction.
std::string console_actor(const Config& config) {
    return "@console:" + config.server_name;
}

// Loads the config the way the server does, including the validation pass, so
// a config this tool accepts is one the server would also start with.
// Returns false and explains on `out` when it cannot.
bool load_config(const std::string& path, Config& config, std::ostream& out) {
    try {
        config = Config::load(path);
    } catch (const std::exception& e) {
        out << "error: failed to load config from " << path << ": " << e.what() << "\n";
        return false;
    }
    Config::validate(config);
    return true;
}

// The stopped-server check. See the header for why a live server must not be
// written behind: it is a stream-position collision, not a lock contention
// problem, so SQLite will happily let this succeed and break the server later.
bool refuse_if_running(const Config& config, const ListenProbe& probe, std::ostream& out) {
    if (!probe(config.bind_address, config.port)) return false;
    out << "error: something is listening on " << config.bind_address << ":" << config.port
        << ", which means the server is probably still running.\n"
           "       Stop it first. Writing role state behind a live server makes the two\n"
           "       processes hand out the same event stream positions, and the server\n"
           "       fails on its NEXT message, not on this command.\n"
           "       (If the server runs in a container, run this inside the same network\n"
           "       namespace — `docker compose run --rm ...` — not on the host.)\n";
    return true;
}

int cmd_list_users(const CommonArgs& args, std::ostream& out, const ListenProbe& probe) {
    Config config;
    if (!load_config(args.config_path, config, out)) return 1;
    if (refuse_if_running(config, probe, out)) return 1;

    // Read-only, but gated on the same stopped-server check as the write
    // commands on purpose: this exists to tell an operator which id to pass to
    // grant-admin, and an operator who can run it against a live server will
    // reasonably assume the next command works too.
    SqliteStore store(config.database_path);
    store.initialize();

    auto users = store.list_users_with_created_at();
    if (users.empty()) {
        out << "no accounts in " << config.database_path << "\n";
        return 0;
    }

    out << users.size() << " account(s) in " << config.database_path
        << ", oldest first:\n";
    for (const auto& [user_id, created_at] : users) {
        auto display = store.get_display_name(user_id);
        auto roles = store.get_member_role_ids(user_id);
        const bool is_admin = std::find(roles.begin(), roles.end(),
                                        std::string(permission::role_id::kAdmin)) != roles.end();
        out << "  " << user_id;
        if (display && !display->empty()) out << "  (" << log_safe(*display) << ")";
        if (is_admin) out << "  [admin]";
        out << "  created_at=" << created_at << "\n";
    }
    // Printed unconditionally rather than only when no admin exists. The
    // lockout this tool answers is NOT "nobody holds admin" — on production
    // somebody did — it is "nobody who holds admin can sign in from the client
    // they are actually using", which this listing cannot tell from a healthy
    // server.
    out << "\nThe display name is what a client shows; it is NOT the account. "
           "Two rows here\ncan be the same human — see grant-admin below, and "
           "account linking.\n";
    return 0;
}

int cmd_grant_admin(const CommonArgs& args, std::ostream& out, const ListenProbe& probe) {
    Config config;
    if (!load_config(args.config_path, config, out)) return 1;
    if (refuse_if_running(config, probe, out)) return 1;

    if (!UserId::is_valid(args.user_id)) {
        out << "error: " << log_safe(args.user_id)
            << " is not a valid user id (expected @localpart:server)\n";
        return 2;
    }

    SqliteStore store(config.database_path);
    store.initialize();

    if (!store.user_exists(args.user_id)) {
        out << "error: no account " << log_safe(args.user_id) << " in "
            << config.database_path << "\n"
            << "       run `bsfchat-server list-users --config " << args.config_path
            << "` to see the ids that exist.\n";
        // Deliberately does NOT create the account. A recovery tool that
        // conjures an account out of a typo hands admin to a user id nobody
        // can sign in as, and leaves the real lockout in place.
        return 1;
    }

    // The role DEFINITIONS have to exist already. They are seeded by
    // bootstrap_roles on every server start, so on any database that has run a
    // server they do; refusing here rather than seeding them keeps this tool to
    // one job. Seeding would also mean choosing an owner, which is the decision
    // that produced the lockout in the first place.
    auto defined = store.get_server_roles();
    const bool admin_defined = std::any_of(
        defined.begin(), defined.end(),
        [](const ServerRole& r) { return r.id == permission::role_id::kAdmin; });
    if (!admin_defined) {
        out << "error: this database has no `admin` role defined yet.\n"
               "       Start the server once (it seeds the default roles), stop it, "
               "then run this again.\n";
        return 1;
    }

    auto current = store.get_member_role_ids(args.user_id);
    if (std::find(current.begin(), current.end(),
                  std::string(permission::role_id::kAdmin)) != current.end()) {
        // No write, and therefore no audit record. Matches the rest of the role
        // path, where a write that changes nothing records nothing — an audit
        // log full of "granted admin to the account that already had admin"
        // teaches a reader to skim past the line that matters.
        out << args.user_id << " already holds the admin role; nothing to do.\n";
        return 0;
    }

    // @everyone is added when the account has no assignment row at all, which
    // is the state an account is in before bootstrap_roles has seen it. Handing
    // out admin WITHOUT @everyone would produce a member whose base permissions
    // come from one role, and the next bootstrap pass would skip them forever
    // after (it only writes to accounts with an empty assignment list).
    std::vector<std::string> updated = current;
    if (updated.empty()) updated.push_back(std::string(permission::role_id::kEveryone));
    updated.push_back(std::string(permission::role_id::kAdmin));

    MemberRolesContent content;
    content.role_ids = updated;
    nlohmann::json j;
    to_json(j, content);

    // THE choke point. Going through it, rather than writing the server_state
    // row directly, is the entire reason this command exists: it takes the
    // authoritative row, records the audit entry, and mirrors the change into a
    // room so clients pick it up on their next sync. The SSH recovery that
    // prompted this skipped all three.
    write_server_scoped_state(store, config, std::string(event_type::kMemberRoles),
                              args.user_id, j.dump(), pick_server_state_mirror_room(store),
                              console_actor(config));

    out << "granted the admin role to " << args.user_id << "\n"
        << "  roles now: ";
    for (size_t i = 0; i < updated.size(); ++i) {
        out << (i ? ", " : "") << updated[i];
    }
    out << "\n  recorded in the audit log as " << console_actor(config) << "\n"
        << "Start the server again; the client picks the change up on its next sync.\n";
    return 0;
}

} // namespace

bool default_listen_probe(const std::string& address, int port) {
    // IPv6 is detected by a colon, which is safe because this value is an
    // address from the operator's own config and not a hostname: Config does
    // not accept one for bind_address.
    const bool v6 = address.find(':') != std::string::npos;
    const int fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        // Cannot tell. Say so rather than silently reporting "free": the whole
        // value of this check is that an operator trusts its answer.
        get_logger()->warn("could not open a probe socket to check whether the server is "
                           "running; verify it is stopped yourself");
        return false;
    }

    // NO SO_REUSEADDR and NO SO_REUSEPORT, deliberately. Both exist to let a
    // second bind succeed, which is the exact opposite of what is being asked
    // here — with them set, this probe would report a free port while the
    // server was listening on it, and the refusal above would never fire.
    int rc = -1;
    if (v6) {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(static_cast<uint16_t>(port));
        if (::inet_pton(AF_INET6, address.c_str(), &addr.sin6_addr) != 1) {
            addr.sin6_addr = in6addr_any;
        }
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    } else {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        if (::inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        rc = ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    }
    const int err = errno;
    ::close(fd);

    if (rc == 0) return false;               // bound it ourselves: nothing there
    if (err == EADDRINUSE) return true;      // the answer we are looking for
    // EACCES on a privileged port, or anything else: we could not bind for a
    // reason that says nothing about whether a server is running. Report "not
    // running" so the tool stays usable, and let the operator's own procedure
    // carry it — refusing outright would make an unprivileged recovery
    // impossible on a server bound to :443.
    get_logger()->warn("probe of {}:{} was inconclusive (errno {}); verify the server is "
                       "stopped yourself", address, port, err);
    return false;
}

bool is_admin_subcommand(const std::string& token) {
    return token == "grant-admin" || token == "list-users";
}

void print_admin_usage(std::ostream& out) {
    out << "admin subcommands (run with the server STOPPED):\n"
           "  list-users  --config <path>\n"
           "      Every account, oldest first, with its roles. Use it to find the\n"
           "      exact user id to grant admin to.\n"
           "  grant-admin --config <path> --user <@user:server>\n"
           "      Give that account the admin role. Idempotent. Goes through the same\n"
           "      audited, sync-mirrored write path the API uses.\n"
           "\n"
           "Both require --config: they will not guess which database to open.\n";
}

int run_admin_cli(const std::vector<std::string>& args, std::ostream& out, ListenProbe probe) {
    if (args.empty()) {
        print_admin_usage(out);
        return 2;
    }
    const std::string& command = args.front();

    const bool wants_user = (command == "grant-admin");
    auto parsed = parse_common(args, wants_user);
    if (!parsed.ok) {
        out << "error: " << parsed.error << "\n\n";
        print_admin_usage(out);
        return 2;
    }

    try {
        if (command == "list-users") return cmd_list_users(parsed, out, probe);
        if (command == "grant-admin") return cmd_grant_admin(parsed, out, probe);
    } catch (const std::exception& e) {
        // A schema too new for this build, an unreadable database, a disk
        // error. One message, non-zero exit, nothing half-written: every write
        // above is a single call into the store, which is itself transactional.
        out << "error: " << e.what() << "\n";
        return 1;
    }

    out << "error: unknown subcommand: " << log_safe(command) << "\n\n";
    print_admin_usage(out);
    return 2;
}

} // namespace bsfchat
