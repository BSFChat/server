import io

P = '/Users/josh/dev/gamechat/server/tests/test_permission_scope.cpp'
s = io.open(P, encoding='utf-8').read()


def sub(old, new, count=1):
    global s
    assert s.count(old) == count, 'expected %d occurrences, found %d for: %r' % (
        count, s.count(old), old[:90])
    s = s.replace(old, new)


# ── 1. A reason-asserting forbidden matcher ──────────────────────────────
sub('''::testing::AssertionResult IsForbidden(const httplib::Response& res) {
    if (res.status == 403) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                         << ", body: " << res.body;
}''',
'''::testing::AssertionResult IsForbidden(const httplib::Response& res) {
    if (res.status == 403) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                         << ", body: " << res.body;
}

// A 403 refused for the REASON given, not merely a 403.
//
// This distinction is load-bearing and was found by mutation testing: every
// moderation endpoint refuses for two separate reasons — insufficient permission
// and insufficient rank — and an actor at the same role position as their target
// is refused by RANK whatever the permission check decided. A scope-regression
// test written with a same-rank actor therefore stays green after the scope fix is
// reverted, which is a test that cannot fail. Asserting the reason, and giving the
// actor a rank above the target, is what makes these tests actually bite.
::testing::AssertionResult IsForbiddenBecause(const httplib::Response& res,
                                              const std::string& needle) {
    if (res.status != 403) {
        return ::testing::AssertionFailure() << "expected 403, got status " << res.status
                                             << ", body: " << res.body;
    }
    if (res.body.find(needle) == std::string::npos) {
        return ::testing::AssertionFailure()
               << "403 for the wrong reason: expected a message containing \\"" << needle
               << "\\", got: " << res.body;
    }
    return ::testing::AssertionSuccess();
}''')

# ── 2. A role that outranks a plain member but grants nothing extra ──────
sub('''        // Nickname management without ADMINISTRATOR, so MANAGE_NICKNAMES is tested
        // on its own flag and not on the god-mode short-circuit.
        content.roles.push_back(role("nickmod", 20, everyone_flags | permission::kManageNicknames));''',
'''        // Outranks a plain member and grants NOTHING beyond @everyone. Required by
        // every "lacks the permission" test: an actor at the same position as the
        // target is refused by the RANK check regardless of the permission check, so
        // without this role those tests pass whether or not the scope fix is present.
        content.roles.push_back(role("helper", 5, everyone_flags));
        // Nickname management without ADMINISTRATOR, so MANAGE_NICKNAMES is tested
        // on its own flag and not on the god-mode short-circuit.
        content.roles.push_back(role("nickmod", 20, everyone_flags | permission::kManageNicknames));''')

# ── 3. KICK override test ────────────────────────────────────────────────
sub('''TEST(ModerationScope, PerChannelOverrideDoesNotConferKick) {
    Fixture f("kick-override");
    f.seed_roles();
    auto member = f.add_user("member");
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);

    // The grant a per-channel editor could plausibly write, if it offered the
    // flag at all. It must confer nothing: kick is server-wide only.
    f.set_override(room, "user:" + member, permission::kKickMembers);

    // The engine itself must disagree between the two scopes, or the handler
    // assertion below would pass for the wrong reason.
    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(member, room, permission::kKickMembers))
        << "override did not apply at channel scope; the test proves nothing";
    ASSERT_FALSE(perms.can(member, std::string(), permission::kKickMembers));

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &RoomHandler::handle_kick, kick_path(room),
                                 "token-member", target_body(victim))));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
}''',
'''TEST(ModerationScope, PerChannelOverrideDoesNotConferKick) {
    Fixture f("kick-override");
    f.seed_roles();
    // "helper" outranks a plain member, so the rank check PASSES and the only thing
    // that can refuse this request is the permission check. With a same-rank actor
    // this test stayed green even with the scope fix reverted.
    auto member = f.add_user("member", {"helper"});
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);

    // The grant a per-channel editor could plausibly write, if it offered the
    // flag at all. It must confer nothing: kick is server-wide only.
    f.set_override(room, "user:" + member, permission::kKickMembers);

    // The engine itself must disagree between the two scopes, or the handler
    // assertion below would pass for the wrong reason.
    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(member, room, permission::kKickMembers))
        << "override did not apply at channel scope; the test proves nothing";
    ASSERT_FALSE(perms.can(member, std::string(), permission::kKickMembers));
    ASSERT_TRUE(perms.outranks(member, victim))
        << "actor must outrank the target, or the rank check refuses regardless of scope";

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_kick, kick_path(room),
                                        "token-member", target_body(victim)),
                                   "Insufficient permissions to kick"));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
}''')

# ── 4. BAN override test ─────────────────────────────────────────────────
sub('''    Fixture f("ban-override");
    f.seed_roles();
    auto member = f.add_user("member");
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.set_override(room, "user:" + member, permission::kBanMembers);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &RoomHandler::handle_ban, ban_path(room),
                                 "token-member", target_body(victim))));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
}''',
'''    Fixture f("ban-override");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.set_override(room, "user:" + member, permission::kBanMembers);

    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_ban, ban_path(room),
                                        "token-member", target_body(victim)),
                                   "Insufficient permissions to ban"));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kJoin);
}''')

# ── 5. UNBAN override test ───────────────────────────────────────────────
sub('''    Fixture f("unban-override");
    f.seed_roles();
    auto member = f.add_user("member");
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.store->set_membership(room, victim, std::string(membership::kBan));
    f.set_override(room, "user:" + member, permission::kBanMembers);

    // Unban must move with ban. If it stayed channel-scoped, an override would let
    // someone lift bans they could never have placed.
    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &RoomHandler::handle_unban, unban_path(room),
                                 "token-member", target_body(victim))));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan);
}''',
'''    Fixture f("unban-override");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.store->set_membership(room, victim, std::string(membership::kBan));
    f.set_override(room, "user:" + member, permission::kBanMembers);

    // Unban must move with ban. If it stayed channel-scoped, an override would let
    // someone lift bans they could never have placed.
    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_unban, unban_path(room),
                                        "token-member", target_body(victim)),
                                   "Insufficient permissions to unban"));
    EXPECT_EQ(f.store->get_membership(room, victim), membership::kBan);
}''')

# ── 6. the state-PUT bypass test ─────────────────────────────────────────
sub('''    Fixture f("statput-override");
    f.seed_roles();
    auto member = f.add_user("member");
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.set_override(room, "user:" + member, permission::kKickMembers);''',
'''    Fixture f("statput-override");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");
    auto room = f.add_channel(member, "general");
    f.join(room, victim);
    f.set_override(room, "user:" + member, permission::kKickMembers);''')

sub('''    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &RoomHandler::handle_set_state,
                                 member_state_path(room, victim), "token-member",
                                 json{{"membership", membership::kBan}}.dump())));

    // Asserted on the EVENT, not on get_membership.''',
'''    RoomHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &RoomHandler::handle_set_state,
                                        member_state_path(room, victim), "token-member",
                                        json{{"membership", membership::kBan}}.dump()),
                                   "Insufficient permissions for this state event"));

    // Asserted on the EVENT, not on get_membership.''')

# ── 7. nickname: other-without-MANAGE ────────────────────────────────────
sub('''    Fixture f("nick-other-no");
    f.seed_roles();
    // Has CHANGE_NICKNAME (via @everyone) but not MANAGE_NICKNAMES. Renaming
    // yourself must not imply renaming anybody else.
    auto member = f.add_user("member");
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &ProfileHandler::handle_put_nickname,
                                 nickname_path(target), "token-member",
                                 nickname_body("Renamed"))));
    EXPECT_FALSE(f.store->get_nickname(target).has_value());
}''',
'''    Fixture f("nick-other-no");
    f.seed_roles();
    // Has CHANGE_NICKNAME (via @everyone) but not MANAGE_NICKNAMES. Renaming
    // yourself must not imply renaming anybody else.
    //
    // "helper" so the actor outranks the target: at equal rank this is refused by
    // the rank check and the test would pass even if the gate used the wrong flag.
    auto member = f.add_user("member", {"helper"});
    auto target = f.add_user("target");

    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &ProfileHandler::handle_put_nickname,
                                        nickname_path(target), "token-member",
                                        nickname_body("Renamed")),
                                   "other members' nicknames"));
    EXPECT_FALSE(f.store->get_nickname(target).has_value());
}''')

# ── 8. nickname: channel override confers neither flag ───────────────────
sub('''    Fixture f("nick-override");
    f.seed_roles(permission::kEveryoneDefault & ~permission::kChangeNickname);
    auto member = f.add_user("member");
    auto target = f.add_user("target");
    auto room = f.add_channel(member, "general");
    f.join(room, target);
    f.set_override(room, "user:" + member,
                   permission::kChangeNickname | permission::kManageNicknames);

    // A nickname is one value for the whole server. A channel-scoped grant of it
    // would be meaningless, so it must not work.
    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbidden(call(handler, &ProfileHandler::handle_put_nickname,
                                 nickname_path(member), "token-member",
                                 nickname_body("Self"))));
    EXPECT_TRUE(IsForbidden(call(handler, &ProfileHandler::handle_put_nickname,
                                 nickname_path(target), "token-member",
                                 nickname_body("Other"))));
}''',
'''    Fixture f("nick-override");
    f.seed_roles(permission::kEveryoneDefault & ~permission::kChangeNickname);
    auto member = f.add_user("member", {"helper"}); // outranks target
    auto target = f.add_user("target");
    auto room = f.add_channel(member, "general");
    f.join(room, target);
    f.set_override(room, "user:" + member,
                   permission::kChangeNickname | permission::kManageNicknames);

    // The override really does grant both flags at channel scope, so these
    // refusals can only come from the checks being evaluated at server scope.
    PermissionsEngine perms(*f.store, f.config);
    ASSERT_TRUE(perms.can(member, room, permission::kChangeNickname));
    ASSERT_TRUE(perms.can(member, room, permission::kManageNicknames));
    ASSERT_TRUE(perms.outranks(member, target));

    // A nickname is one value for the whole server. A channel-scoped grant of it
    // would be meaningless, so it must not work.
    ProfileHandler handler(*f.store, *f.sync, f.config);
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &ProfileHandler::handle_put_nickname,
                                        nickname_path(member), "token-member",
                                        nickname_body("Self")),
                                   "change your nickname"));
    EXPECT_TRUE(IsForbiddenBecause(call(handler, &ProfileHandler::handle_put_nickname,
                                        nickname_path(target), "token-member",
                                        nickname_body("Other")),
                                   "other members' nicknames"));
}''')

# ── 9. audit "refused records nothing" — use the helper actor too ────────
sub('''    Fixture f("audit-refused");
    f.seed_roles();
    auto member = f.add_user("member");
    auto victim = f.add_user("victim");''',
'''    Fixture f("audit-refused");
    f.seed_roles();
    auto member = f.add_user("member", {"helper"}); // outranks victim; see kick test
    auto victim = f.add_user("victim");''')

io.open(P, 'w', encoding='utf-8').write(s)
print('all substitutions applied')
