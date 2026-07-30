import io

p = '/Users/josh/dev/gamechat/server/tests/test_permission_scope.cpp'
d = io.open(p, encoding='utf-8').read()
lines = d.split('\n')

start = next(i for i, l in enumerate(lines)
             if l.startswith('TEST(') and 'RejectsMxidShapedAndUnsafeCharacters' in l)
end = next(i for i, l in enumerate(lines)
           if l.startswith('TEST(') and 'RejectsMalformedUtf8AtTheValidator' in l)
print('replacing source lines', start + 1, 'through', end)

new = '''TEST(NicknameValidation, RejectsMxidShapedAndUnsafeCharacters) {
    Fixture f("nick-unsafe");
    f.seed_roles();
    auto member = f.add_user("member");
    ProfileHandler handler(*f.store, *f.sync, f.config);

    // Bodies are hand-written JSON carrying \\uXXXX escapes rather than dumped from
    // a json object. That is the shape a real request takes: a control or invisible
    // character survives JSON transport only as an escape, and the parser turns it
    // back into the real character before the validator sees it. Dumping a json
    // object holding the raw character would instead throw inside the test and
    // prove nothing about the handler.
    const std::vector<std::pair<std::string, std::string>> bad_bodies = {
        {"mxid shape",             "{\\"nickname\\":\\"@someone:test\\"}"},
        {"newline",                "{\\"nickname\\":\\"Bob\\\\u000aAdmin\\"}"},
        {"carriage return",        "{\\"nickname\\":\\"Bob\\\\u000dAdmin\\"}"},
        {"tab",                    "{\\"nickname\\":\\"Bob\\\\u0009Admin\\"}"},
        {"nul",                    "{\\"nickname\\":\\"Bob\\\\u0000Admin\\"}"},
        {"C1 control",             "{\\"nickname\\":\\"Bob\\\\u0085Admin\\"}"},
        {"soft hyphen",            "{\\"nickname\\":\\"Bo\\\\u00adb\\"}"},
        {"right-to-left override", "{\\"nickname\\":\\"Bob\\\\u202enimda\\"}"},
        {"left-to-right mark",     "{\\"nickname\\":\\"Bob\\\\u200e\\"}"},
        {"zero width space",       "{\\"nickname\\":\\"Bo\\\\u200bb\\"}"},
        {"bidi isolate",           "{\\"nickname\\":\\"\\\\u2066Bob\\"}"},
        {"word joiner",            "{\\"nickname\\":\\"Bo\\\\u2060b\\"}"},
        {"byte order mark",        "{\\"nickname\\":\\"\\\\ufeffBob\\"}"},
        {"too long",               "{\\"nickname\\":\\"" + std::string(33, 'a') + "\\"}"},
    };

    for (const auto& [label, body] : bad_bodies) {
        auto res = call(handler, &ProfileHandler::handle_put_nickname, nickname_path(member),
                        "token-member", body);
        EXPECT_TRUE(IsBadRequest(res)) << "accepted " << label;
        EXPECT_FALSE(f.store->get_nickname(member).has_value()) << "stored " << label;
    }
}

'''

lines[start:end] = new.split('\n')[:-1]
out = '\n'.join(lines)
assert chr(0) not in out, 'NUL byte still present'
io.open(p, 'w', encoding='utf-8').write(out)
print('written; NUL count =', out.count(chr(0)))
