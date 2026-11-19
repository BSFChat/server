#pragma once

#include <string_view>

namespace bsfchat {

// Does this message text address the whole room — "@everyone", "@here" or
// "@room" — the way the client would render it (audit 3)?
//
// It used to be a plain substring test, so "ops@hereford.example" and a quoted
// `@everyone` inside a code span were refused as mass mentions. Now it matches
// the client's MentionRenderer: a token, not part of a word (the characters
// either side are not letters, digits or '_'), case-insensitive, and never
// inside a code span or block, a link, or a URL.
//
// `html` selects formatted_body rules: tags are skipped, and text inside
// <code>, <pre> and <a> is inert. Otherwise Markdown-ish rules apply to the
// plain body: text between backticks (inline or fenced) is inert.
[[nodiscard]] bool text_mentions_everyone(std::string_view text, bool html);

} // namespace bsfchat
