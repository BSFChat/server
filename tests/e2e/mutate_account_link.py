#!/usr/bin/env python3
"""Mutation harness for account linking (one human, one account).

A passing suite proves nothing on its own: it may be passing because the
property holds, or because nothing is checking it. Each mutation below breaks
exactly one property of the feature and asserts that the named tests FAIL. A
mutation that leaves the suite green is a test that was not testing anything.

The first mutation is special: it is not an invented defect but the code
EXACTLY AS IT WAS before this work — the login path never consulting the link
table. That is the shape that produced three accounts for one person on
production, and if the suite stays green under it then nothing here is
actually covering the feature.

Run from anywhere:  python3 server/tests/e2e/mutate_account_link.py
It restores the tree and rebuilds clean on the way out, including after a crash
in the middle of a case.
"""

import subprocess
import sys
from pathlib import Path

from mutate_common import MutationGuard, build_dir, cmake_build, require_build, server_root

# Resolved from this script's own location, so a run from a worktree mutates
# THAT worktree. See mutate_common.
SERVER = server_root()
BUILD = build_dir(SERVER, "build-al")

AUTH = SERVER / "src/api/AuthHandler.cpp"
STORE = SERVER / "src/store/SqliteStore.cpp"
AUDIT = SERVER / "src/audit/AuditLog.cpp"


class Mutation:
    """`files` is a list of (path, edits); each edit is an (old, new) pair that
    must match exactly once in that file.

    Several files are sometimes needed to express a mutation FAITHFULLY. The
    takeover case below is the example: the handler refuses a conflict AND the
    store's INSERT does not upsert, so patching either one alone leaves the
    other refusing — and the harness would report a catch for a hole that is
    not open.
    """

    def __init__(self, name, files, must_fail, must_pass=""):
        self.name = name
        self.files = files
        self.must_fail = must_fail
        self.must_pass = must_pass


MUTATIONS = [
    Mutation(
        "L1: the login path never consults the link table (the code before this work)",
        [(AUTH, [("        std::string user_id = linked ? *linked\n"
          "                                     : shadow_user_id_for_subject(claims->sub,\n"
          "                                                                  config_.server_name);",
          "        std::string user_id = shadow_user_id_for_subject(claims->sub,\n"
          "                                                         config_.server_name);")])],
        "AccountLinkTest.AfterLinkingTheIdentitySignsInAsTheExistingAccount"
        ":AccountLinkTest.TheSupersededAccountKeepsItsUserIdAndItsMessages",
        # Control: an UNLINKED identity must behave identically before and
        # after. If this also goes red the mutation broke ordinary identity
        # login rather than the linking property, and the result means nothing.
        "AccountLinkTest.AnUnlinkedIdentityStillGetsItsOwnAccountExactlyAsBefore",
    ),
    Mutation(
        "L2: an identity can be moved onto whichever account asks last (takeover)",
        # BOTH defences, because either alone still refuses and a one-file
        # version would report a catch for a hole that is not open. The handler
        # stops reporting the conflict; the store starts upserting.
        [(AUTH,
          # THREE edits, not two. The handler refuses a known conflict up front
          # AND reports one from the insert's return value AND the insert does
          # not upsert; an earlier version of this case patched only the last
          # two, the up-front check still answered 409, and the harness
          # correctly reported the mutant as surviving.
          [("    // Already linked? Three distinct answers, and they must stay distinct.\n"
            "    if (auto existing = store_.find_linked_user(claims->iss, claims->sub)) {",
            "    // Already linked? Three distinct answers, and they must stay distinct.\n"
            "    if (false) if (auto existing = store_.find_linked_user(claims->iss, claims->sub)) {"),
           ("    if (!store_.link_identity(claims->iss, claims->sub, *actor, *actor, now)) {",
            "    store_.link_identity(claims->iss, claims->sub, *actor, *actor, now);\n"
            "    if (false) {")]),
         (STORE,
          [('"INSERT OR IGNORE INTO linked_identities "',
            '"INSERT OR REPLACE INTO linked_identities "')])],
        "AccountLinkTest.AnIdentityAlreadyLinkedElsewhereCannotBeTakenOver"
        ":AccountLinkTest.LinkingTheSameIdentityTwiceIsIdempotent",
        # Control: linking an UNCLAIMED identity must still work. If this goes
        # red the mutation stopped links happening at all rather than opening
        # the takeover, and the result means nothing.
        "AccountLinkTest.AfterLinkingTheIdentitySignsInAsTheExistingAccount",
    ),
    Mutation(
        "L3: the store upserts, so a racing second link silently re-points the identity",
        # The store guard ON ITS OWN. Not detectable through the endpoint — the
        # handler refuses first — which is the point of having both, and which
        # is why there is a store-level test for it.
        [(STORE,
          [('"INSERT OR IGNORE INTO linked_identities "',
            '"INSERT OR REPLACE INTO linked_identities "')])],
        "AccountLinkTest.TheStoreItselfRefusesToRepointAnIdentity",
        "AccountLinkTest.AnIdentityAlreadyLinkedElsewhereCannotBeTakenOver",
    ),
    Mutation(
        "L4: the bearer token is not required, so an identity picks its own account",
        [(AUTH,
          [("    auto actor = authenticate(store_, req.get_header_value(\"Authorization\"));\n"
            "    if (!actor) {\n"
            "        res.status = 401;\n"
            "        res.set_content(auth_error(req.get_header_value(\"Authorization\")).to_json().dump(),\n"
            "                        \"application/json\");\n"
            "        return;\n"
            "    }\n"
            "\n"
            "    // Rate-limited on the same per-address budget as /login",
            "    auto actor = authenticate(store_, req.get_header_value(\"Authorization\"));\n"
            "    if (!actor) actor = std::string(\"@josh:test\");\n"
            "\n"
            "    // Rate-limited on the same per-address budget as /login")])],
        "AccountLinkTest.LinkingRequiresASessionForTheAccountItAttachesTo",
    ),
    Mutation(
        "L5: the id_token is not verified, so asserting an identity is enough",
        [(AUTH,
          [("    if (!claims) {\n"
            "        record_failure(client, {});\n"
            "        send_error(res, 403, MatrixError::forbidden(refusal));\n"
            "        return;\n"
            "    }",
            "    if (!claims) {\n"
            "        JwtClaims forged;\n"
            "        forged.iss = config_.identity ? config_.identity->provider_url : std::string();\n"
            "        forged.sub = \"a5cdbefe\";\n"
            "        claims = forged;\n"
            "    }")])],
        "AccountLinkTest.AssertingAnIdentityWithoutAVerifiableTokenAttachesNothing",
    ),
    Mutation(
        "L6: a banned account can acquire a new way to sign in",
        [(AUTH,
          [("    if (store_.is_server_banned(*actor) ||\n"
            "        (!shadow.empty() && store_.is_server_banned(shadow))) {",
            "    if (false) {")])],
        "AccountLinkTest.ABannedAccountCannotAcquireANewWayToSignIn"
        ":AccountLinkTest.ABannedIdentityCannotBeLaunderedOntoAnUnbannedAccount",
    ),
    Mutation(
        "L7: the superseded account keeps its live sessions",
        [(AUTH,
          [("        const int revoked = store_.delete_all_tokens_for_user(shadow);",
            "        const int revoked = 0;")])],
        "AccountLinkTest.LinkingRevokesTheSupersededAccountsLiveSessions",
        "AccountLinkTest.TheSupersededAccountKeepsItsUserIdAndItsMessages",
    ),
    Mutation(
        "L8: a linked login lets the identity provider rewrite the display name",
        [(AUTH,
          [("        if (!linked && claims->name) {", "        if (claims->name) {")])],
        "AccountLinkTest.ALinkedLoginDoesNotLetTheProviderRenameTheAccount",
        "AccountLinkTest.AnUnlinkedIdentityStillGetsItsOwnAccountExactlyAsBefore",
    ),
    Mutation(
        "L9: a bot account may link a human identity",
        [(AUTH, [("    if (store_.is_bot(*actor)) {", "    if (false) {")])],
        "AccountLinkTest.ABotCannotLinkAnIdentity",
    ),
    Mutation(
        "L10: the provider subject is written into the audit log",
        [(AUDIT,
          [('    nlohmann::json after = {{"issuer", issuer}};',
            '    nlohmann::json after = {{"issuer", issuer}, {"subject", "a5cdbefe"}};')])],
        "AccountLinkTest.TheProviderSubjectIsNotRecordedAsAClaimOfItsOwn"
        ":AccountLinkTest.LinkingIsAuditedWithExactlyTheIssuerAndTheSupersededAccount",
    ),
    # ── C1: the token is bound to THIS server (identity audit 2026-09) ──
    Mutation(
        "C1a: the audience is the shared client id again (the code before the C1 fix)",
        [(AUTH, [("    const std::string audience = expected_identity_audience(config_);\n",
                  "    const std::string audience = config_.identity->client_id;\n")])],
        "AccountLinkTest.C1_TheLegacyClientIdAudienceSignsNobodyIn:"
        "AccountLinkTest.C1_AReplayedTokenCannotHijackAnIdentityThroughLinkIdentity",
    ),
    Mutation(
        "C1b: an underivable audience falls through to jwt_verify's unchecked mode",
        [(AUTH, [("    if (audience.empty()) {\n"
                  "        log->error(\"Refused an identity token: this server has no usable public URL \"\n",
                  "    if (false) {\n"
                  "        log->error(\"Refused an identity token: this server has no usable public URL \"\n")])],
        "AccountLinkTest.AnUnusablePublicUrlRefusesEveryToken",
    ),
    Mutation(
        "C1c: a token is accepted however many times it is presented",
        [(AUTH, [("    if (!oidc_auth_->first_presentation(claims->iss, claims->sub, *claims->nonce,\n",
                  "    if (false && !oidc_auth_->first_presentation(claims->iss, claims->sub, *claims->nonce,\n")])],
        "AccountLinkTest.AnIdentityTokenIsAcceptedOnce",
    ),
    Mutation(
        "C1d: azp is not checked, so another relying party's token signs in here",
        [(AUTH, [("    if (!client_id.empty() && claims->azp.value_or(std::string()) != client_id) {\n",
                  "    if (false) {\n")])],
        "AccountLinkTest.ATokenIssuedToAnotherClientIsRefused",
    ),
    Mutation(
        "C1e: a token without a nonce is accepted",
        [(AUTH, [("    if (!claims->nonce || claims->nonce->empty()) {\n",
                  "    if (!claims->nonce) claims->nonce = std::string(\"\");\n    if (false) {\n")])],
        "AccountLinkTest.ATokenWithoutANonceIsRefused",
    ),
]


def object_files(source: Path):
    """Every compiled object for `source`, across every CMake target."""
    stem = source.name + ".o"
    return [p for p in BUILD.rglob(stem) if "_deps" not in str(p)]


def build():
    r = cmake_build(BUILD)
    return r.returncode == 0, r.stdout + r.stderr


def run_tests(gtest_filter):
    r = subprocess.run([str(BUILD / "tests/server_tests"),
                        "--gtest_filter=" + gtest_filter, "--gtest_brief=1"],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


def apply_edits(text, edits):
    for old, new in edits:
        count = text.count(old)
        if count != 1:
            return None, f"pattern matched {count} times, expected exactly 1: {old[:60]!r}"
        text = text.replace(old, new, 1)
    return text, None


def main():
    require_build(BUILD)
    # Snapshots each file before it is mutated and reverts however this process
    # ends — normally, on an exception, on Ctrl-C or a kill. recover() first
    # repairs anything a SIGKILLed run left applied.
    guard = MutationGuard(SERVER, builds=[BUILD])
    guard.recover()
    problems = []
    caught = 0

    for m in MUTATIONS:
        # Every file is snapshotted and patched before anything is rebuilt: a
        # mutation spanning two files is only faithful if both halves are in
        # the tree at once.
        err = None
        patched = []
        for path, edits in m.files:
            original = guard.protect(path).decode()
            mutated, err = apply_edits(original, edits)
            if err:
                break
            path.write_text(mutated)
            patched.append(path)
        if err:
            problems.append(f"{m.name}: {err}")
            print(f"ERROR     {m.name}\n          {err}")
            for path in patched:
                guard.restore(path)
            continue

        # Same-second timestamps: make will happily reuse a stale object.
        for path in patched:
            for obj in object_files(path):
                obj.unlink()
        try:
            ok, log = build()
            if not ok:
                problems.append(f"{m.name}: BUILD FAILED (the mutation does not compile)")
                print(f"ERROR     {m.name}\n          build failed:\n{log[-1200:]}")
                continue
            still_green, _ = run_tests(m.must_fail)
            if still_green:
                problems.append(f"{m.name}: tests still pass -> PROPERTY NOT COVERED")
                print(f"SURVIVED  {m.name}\n          {m.must_fail} still green")
                continue
            note = ""
            if m.must_pass:
                control_ok, _ = run_tests(m.must_pass)
                if control_ok:
                    note = f"  [control {m.must_pass} still green]"
                else:
                    note = (f"  [control {m.must_pass} ALSO RED -- mutation is broader "
                            f"than the property; read it]")
                    problems.append(f"{m.name}: control {m.must_pass} also failed")
            caught += 1
            print(f"caught    {m.name}{note}")
        finally:
            for path in patched:
                guard.restore(path)

    print("\nRestoring the tree and rebuilding clean...")
    guard.restore_all()
    ok, log = build()
    if not ok:
        print("ERROR: clean rebuild FAILED after restore!\n" + log[-2000:])
        return 2
    green, out = run_tests("AccountLinkTest.*")
    print("Clean suite: " + ("green" if green else "RED\n" + out[-3000:]))
    if not green:
        return 2

    print(f"\n{caught}/{len(MUTATIONS)} mutations caught.")
    for p in problems:
        print("  PROBLEM: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
