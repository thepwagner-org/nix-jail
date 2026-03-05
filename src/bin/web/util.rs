//! Shared types and small helper functions used across the web module.

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use std::convert::Infallible;

/// Convenience alias: the single response body type used everywhere in nj-web.
pub type BoxedBody = BoxBody<Bytes, Infallible>;

/// Wrap a byte-convertible value into a `BoxedBody`.
pub fn full_body(s: impl Into<Bytes>) -> BoxedBody {
    Full::new(s.into()).map_err(|e| match e {}).boxed()
}

/// Build a `text/plain` error response.
pub fn error_response(status: StatusCode, msg: &str) -> Response<BoxedBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(full_body(format!("{status}: {msg}\n")))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full_body("internal server error\n"))
                .unwrap_or_else(|_| unreachable!("static response always valid"))
        })
}

/// Build an `application/json` error response.
pub fn json_error(status: StatusCode, msg: &str) -> Response<BoxedBody> {
    let msg_escaped = msg.replace('"', "\\\"");
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full_body(format!(r#"{{"error":"{msg_escaped}"}}"#)))
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "json error failed"))
}

/// Percent-encode a string for use as an RFC 6265 cookie value.
///
/// Encodes all bytes outside the printable ASCII set (0x21–0x7E) and
/// the characters `%`, `;`, `,`, ` ` which have special meaning in cookie syntax.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_graphic() && b != b'%' && b != b';' && b != b',' && b != b'"' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
        }
    }
    out
}

/// Decode a percent-encoded cookie value. Invalid sequences are left as-is.
pub fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(h1), Some(h2)) = (h1, h2) {
                if let Ok(b) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                    out.push(b as char);
                    continue;
                }
            }
            out.push('%');
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract the leftmost subdomain label from a host string.
///
/// Example: `"foo.desktop-17.pwagner.net"` with base `"desktop-17.pwagner.net"` → `"foo"`.
/// Returns `None` for an empty label or multi-level subdomains.
pub fn extract_subdomain<'a>(host: &'a str, base_domain: &str) -> Option<&'a str> {
    let suffix = format!(".{base_domain}");
    let label = host.strip_suffix(suffix.as_str())?;
    // Reject empty or multi-level subdomains (e.g. "a.b.base")
    if label.is_empty() || label.contains('.') {
        return None;
    }
    Some(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subdomain_basic() {
        assert_eq!(
            extract_subdomain("foo.desktop-17.pwagner.net", "desktop-17.pwagner.net"),
            Some("foo")
        );
    }

    #[test]
    fn test_extract_subdomain_no_match() {
        assert_eq!(
            extract_subdomain("desktop-17.pwagner.net", "desktop-17.pwagner.net"),
            None
        );
        assert_eq!(
            extract_subdomain("other.example.com", "desktop-17.pwagner.net"),
            None
        );
    }

    #[test]
    fn test_extract_subdomain_multi_level_rejected() {
        assert_eq!(
            extract_subdomain("a.b.desktop-17.pwagner.net", "desktop-17.pwagner.net"),
            None
        );
    }

    #[test]
    fn test_extract_subdomain_empty_rejected() {
        assert_eq!(
            extract_subdomain(".desktop-17.pwagner.net", "desktop-17.pwagner.net"),
            None
        );
    }

    #[test]
    fn test_percent_encode_plain_ascii() {
        assert_eq!(
            percent_encode("/workspace/projects/nix-jail"),
            "/workspace/projects/nix-jail"
        );
    }

    #[test]
    fn test_percent_encode_special_chars() {
        assert_eq!(percent_encode("/path with spaces"), "/path%20with%20spaces");
        assert_eq!(percent_encode("a;b"), "a%3bb");
        assert_eq!(percent_encode("a%b"), "a%25b");
    }

    #[test]
    fn test_percent_decode_roundtrip() {
        let original = "/workspace/projects/my project";
        assert_eq!(percent_decode(&percent_encode(original)), original);
    }

    #[test]
    fn test_percent_decode_plain() {
        assert_eq!(percent_decode("/workspace/foo"), "/workspace/foo");
    }
}
