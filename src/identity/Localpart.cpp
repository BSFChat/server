#include "identity/Localpart.h"

namespace bsfchat {

namespace {

// Is this one of the three separators registration allows?
//
// They fold to NOTHING rather than to a canonical separator. Folding them to,
// say, `.` would only catch `j.osh` against `j_osh` — the three against each
// other — and would leave `j.osh` against `josh`, which is the cheaper and far
// more common impersonation of the two: a reader scanning a member list does
// not notice a dot, and picking one up is the first thing anyone trying to pass
// as someone else reaches for.
bool is_separator(char c) {
    return c == '.' || c == '_' || c == '-';
}

} // namespace

std::string localpart_skeleton(std::string_view localpart) {
    std::string folded;
    folded.reserve(localpart.size());

    // Pass 1: drop separators and map the digits that read as letters.
    //
    // Separators MUST go first, before the multi-character folding below. A
    // naive implementation that folds `rn` -> `m` on the raw input misses
    // `r.n`, and `r.n` is exactly what someone evading the check would write
    // once they discovered the rule.
    for (char c : localpart) {
        if (is_separator(c)) continue;
        // Registration forces lowercase, but OIDC-derived localparts and any
        // future caller need not, and a skeleton that depended on case would
        // silently stop matching. Fold it here rather than trusting callers.
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        switch (c) {
            // The two pairs that are genuinely indistinguishable in the
            // sans-serif faces a chat client renders names in.
            case '0': folded.push_back('o'); break;
            case '1': folded.push_back('l'); break;
            // Deliberately NOT here, and each for a reason:
            //   `i` -> `l`: the confusable triple is `I`/`l`/`1`, capital i —
            //       and localparts are lowercase, so capital I never appears.
            //       Lowercase `i` carries a dot and reads differently. Folding
            //       it anyway would collide `ian` with `lan`, two real names.
            //   `5` -> `s`, and leetspeak generally (`3`/`e`, `4`/`a`, `7`/`t`):
            //       weak visual confusability, and a trailing digit is how
            //       people ordinarily disambiguate a taken name. `dave5` and
            //       `daves` are two different people far more often than they
            //       are an attack.
            default: folded.push_back(c); break;
        }
    }

    // Pass 2: canonicalise the multi-character confusables by EXPANDING the
    // single glyph, not by contracting the pair.
    //
    // Contracting (`rn` -> `m`) is the obvious direction and it is wrong: it is
    // not confluent. `mrn` contracts to `mm` while `rnm` contracts to `mm` only
    // if you re-scan, and `vvv` contracts to `wv` while the equally
    // lookalike `vw` does not move at all. Expanding has no such ordering: every
    // spelling of the same shape lands on the same all-`rn`/all-`vv` string in
    // a single left-to-right pass.
    std::string skeleton;
    skeleton.reserve(folded.size() * 2);
    for (char c : folded) {
        if (c == 'm') {
            skeleton += "rn";
        } else if (c == 'w') {
            skeleton += "vv";
        } else {
            skeleton.push_back(c);
        }
    }
    return skeleton;
}

} // namespace bsfchat
