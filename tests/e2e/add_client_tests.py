import io

P = '/Users/josh/dev/gamechat/client/tests/test_models.cpp'
s = io.open(P, encoding='utf-8').read()


def sub(a, b, n=1):
    global s
    assert s.count(a) == n, (s.count(a), a[:80])
    s = s.replace(a, b)


# ── helper that builds a member event carrying a nickname ────────────────
sub('''    bsfchat::RoomEvent makeMemberEvent(const std::string& userId,
                                         const std::string& displayName,
                                         const std::string& membership)
    {''',
'''    // A member event as the SERVER writes one once a nickname is set: `displayname`
    // already holds the EFFECTIVE name (the nickname), and `bsfchat.nickname`
    // carries the nickname separately so the UI can tell why the name is what it
    // is. Passing an empty nickname omits the key entirely, which is how "no
    // nickname" is represented on the wire.
    bsfchat::RoomEvent makeMemberEventWithNickname(const std::string& userId,
                                                   const std::string& effectiveName,
                                                   const std::string& nickname,
                                                   const std::string& membership = "join")
    {
        bsfchat::RoomEvent event;
        event.event_id = "$member_" + userId;
        event.sender = userId;
        event.type = std::string(bsfchat::event_type::kRoomMember);
        event.state_key = userId;
        event.origin_server_ts = 1000;
        event.content.data = {
            {"membership", membership},
            {"displayname", effectiveName}
        };
        if (!nickname.empty()) event.content.data["bsfchat.nickname"] = nickname;
        return event;
    }

    bsfchat::RoomEvent makeMemberEvent(const std::string& userId,
                                         const std::string& displayName,
                                         const std::string& membership)
    {''')

# ── the new member-model tests ──────────────────────────────────────────
sub('''    void testMemberListLeave()
    {
        MemberListModel model;
        model.processEvent(makeMemberEvent("@alice:server", "Alice", "join"));
        QCOMPARE(model.rowCount(), 1);

        model.processEvent(makeMemberEvent("@alice:server", "Alice", "leave"));
        QCOMPARE(model.rowCount(), 0);
    }
''',
'''    void testMemberListLeave()
    {
        MemberListModel model;
        model.processEvent(makeMemberEvent("@alice:server", "Alice", "join"));
        QCOMPARE(model.rowCount(), 1);

        model.processEvent(makeMemberEvent("@alice:server", "Alice", "leave"));
        QCOMPARE(model.rowCount(), 0);
    }

    // ── per-server nicknames ────────────────────────────────────────────
    //
    // The rendered name is DisplayNameRole and nothing else: the server resolves
    // nickname-over-global-name and writes the winner into the member event's
    // `displayname`, so no client code has to choose. NicknameRole exists only so
    // admin UI can distinguish "this IS a nickname" from "this is their real name",
    // which is what makes a "Remove nickname" affordance possible.
    void testMemberListNicknamePreferredOverGlobalName()
    {
        MemberListModel model;
        QMap<QString, QString> cache;
        // The global display name is in the cache, as a profile fetch would leave it.
        cache["@alice:server"] = "Alice Anderson";
        model.setDisplayNameCache(&cache);

        model.processEvent(makeMemberEventWithNickname("@alice:server", "Ali", "Ali"));

        auto idx = model.index(0);
        // The nickname wins over the cached global name — and it wins because the
        // event carries it, not because the client re-ranked anything.
        QCOMPARE(model.data(idx, MemberListModel::DisplayNameRole).toString(), "Ali");
        QCOMPARE(model.data(idx, MemberListModel::NicknameRole).toString(), "Ali");
    }

    void testMemberListNicknameAbsentWhenNoneSet()
    {
        MemberListModel model;
        model.processEvent(makeMemberEvent("@bob:server", "Bob", "join"));

        auto idx = model.index(0);
        QCOMPARE(model.data(idx, MemberListModel::DisplayNameRole).toString(), "Bob");
        // Empty, not "Bob": a UI must be able to tell that Bob has NO nickname, or
        // it would offer to remove one that does not exist.
        QCOMPARE(model.data(idx, MemberListModel::NicknameRole).toString(), QString());
    }

    void testMemberListNicknameIsClearedByAnEventWithoutIt()
    {
        MemberListModel model;
        model.processEvent(makeMemberEventWithNickname("@alice:server", "Ali", "Ali"));
        QCOMPARE(model.data(model.index(0), MemberListModel::NicknameRole).toString(), "Ali");

        // Clearing a nickname re-emits the member event with the key ABSENT and the
        // global name restored. A stale nickname surviving that would leave the UI
        // offering "Remove nickname" forever.
        model.processEvent(makeMemberEvent("@alice:server", "Alice Anderson", "join"));
        QCOMPARE(model.rowCount(), 1);
        QCOMPARE(model.data(model.index(0), MemberListModel::DisplayNameRole).toString(),
                 "Alice Anderson");
        QCOMPARE(model.data(model.index(0), MemberListModel::NicknameRole).toString(), QString());
    }

    void testMemberListNicknameLookupByUserId()
    {
        MemberListModel model;
        model.processEvent(makeMemberEventWithNickname("@alice:server", "Ali", "Ali"));
        model.processEvent(makeMemberEvent("@bob:server", "Bob", "join"));

        QCOMPARE(model.nicknameForUser("@alice:server"), "Ali");
        QCOMPARE(model.nicknameForUser("@bob:server"), QString());
        QCOMPARE(model.nicknameForUser("@nobody:server"), QString());
        // displayNameForUser is Q_INVOKABLE so QML can actually call it; it was a
        // plain member function while MessageBubble.qml already called it.
        QCOMPARE(model.displayNameForUser("@alice:server"), "Ali");
    }
''')

io.open(P, 'w', encoding='utf-8').write(s)
print('client model tests added')
