//! Trusted user interaction: password dialogs and unlock coordination.

pub mod pinentry;
pub mod unlock;

/// Longest application-chosen text quoted in a dialog, in characters.
pub const MAX_QUOTED_CHARS: usize = 64;

/// Quotes application-chosen text (an item label) for the trusted dialog
/// text around it. Line breaks and other control characters, bidirectional
/// formatting characters and quotation marks are replaced, and the text is
/// shortened, so it cannot pass for, reorder or push out the daemon's own
/// words.
pub fn quote_untrusted(text: &str) -> String {
    let mut out = String::from("“");
    for (n, c) in text.chars().enumerate() {
        if n == MAX_QUOTED_CHARS {
            out.push('…');
            break;
        }
        out.push(match c {
            // Line breaks, including the Unicode line and paragraph
            // separators, which `is_control` does not cover.
            '\n' | '\r' | '\t' | '\u{2028}' | '\u{2029}' => ' ',
            '"' | '“' | '”' | '„' | '«' | '»' => '\'',
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => '\u{fffd}',
            c if c.is_control() => '\u{fffd}',
            c => c,
        });
    }
    out.push('”');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_text_is_quoted_safely() {
        assert_eq!(quote_untrusted("GitHub"), "“GitHub”");
        assert_eq!(
            quote_untrusted("x\" from host.\nUnlock to continue\u{202e}"),
            "“x' from host. Unlock to continue\u{fffd}”"
        );
        assert_eq!(quote_untrusted("Mail\u{2029}Unlock\u{2028}now\u{85}"), "“Mail Unlock now\u{fffd}”");
        let long = quote_untrusted(&"é".repeat(500));
        assert_eq!(long.chars().count(), MAX_QUOTED_CHARS + 3);
        assert!(long.ends_with("…”"));
    }
}
