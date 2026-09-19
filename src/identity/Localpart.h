#pragma once

#include <string>
#include <string_view>

namespace bsfchat {

// Lookalike ("homoglyph") usernames, as a REGISTRATION policy.
//
// Registration accepts [a-z0-9._-], which contains the classic confusable
// pairs: `l`/`1`, `0`/`o`, `rn`/`m`, `vv`/`w`, and three separators that are
// interchangeable at a glance. `@josh` and `@j0sh` are different accounts that
// look alike in a member list, and that is an impersonation primitive.
//
// The fix is a canonical "skeleton": a lossy folding of a localpart under which
// every variant that reads as the same name maps to the same string. Two names
// collide when their skeletons are equal. This is the same idea as Unicode
// TR39's confusable skeletons, deliberately implemented as a small explicit
// ASCII table instead of pulling in ICU or the full confusables data:
// registration only ever accepts ASCII, this server's user base is
// ASCII-dominant, and the sharper Unicode cases (bidi overrides, zero-width
// joiners, tag characters) are already refused one layer up by
// identity/Nickname for the strings clients actually RENDER. A megabyte of
// confusables table would buy nothing here that these five rules do not.
//
// WHERE THIS IS AND IS NOT APPLIED. It gates new registrations only. It is
// never consulted on the login path, and never on the OIDC auto-create path:
// accounts that predate the rule may well collide under it (see
// SqliteStore::count_localpart_skeleton_collisions, and the count the schema
// migration logs), and refusing to let an existing user log in because their
// name resembles someone else's would be a far worse failure than the one
// this prevents.
//
// The folding is LOSSY and one-way on purpose. It is not an encoding, nothing
// is ever reconstructed from it, and it is not a security boundary on its own:
// it makes casual impersonation fail closed at signup, which is all a
// registration policy can do.
std::string localpart_skeleton(std::string_view localpart);

} // namespace bsfchat
