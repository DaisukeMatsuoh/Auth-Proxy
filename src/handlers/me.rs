use axum::{
    extract::Query,
    response::{Html, IntoResponse, Redirect, Response},
    Extension,
};
use serde::Deserialize;
use crate::middleware::admin::AuthUser;

#[derive(Deserialize)]
pub struct MeQuery {
    pub return_to: Option<String>,
}

/// Validate return_to parameter to prevent open redirects
/// Only allow absolute paths starting with /
fn validate_return_to(return_to: &str) -> Option<String> {
    // Must start with / (relative path)
    // Must not start with // (protocol-relative)
    // Must not contain backslashes (path traversal)
    if return_to.starts_with('/')
        && !return_to.starts_with("//")
        && !return_to.contains('\\')
    {
        Some(return_to.to_string())
    } else {
        None
    }
}

/// Build redirect URL with optional return_to parameter
fn build_redirect_target(base: &str, return_to: Option<&str>) -> String {
    match return_to.and_then(validate_return_to) {
        Some(rt) => {
            let encoded = urlencoding::encode(&rt);
            format!("{}?return_to={}", base, encoded)
        }
        None => base.to_string(),
    }
}

/// Render guest notice page
/// Shown when guest token user accesses /me
#[allow(dead_code)]
fn render_guest_notice(return_to: Option<&str>) -> Html<String> {
    let back_link = if let Some(rt) = return_to {
        if validate_return_to(rt).is_some() {
            // Safely escape HTML in the URL for href attribute
            // encode_double_quoted_attribute (not encode_text) is required here:
            // this value is embedded inside href="...", and encode_text does not
            // escape `"`, which would let return_to break out of the attribute.
            let escaped_url = html_escape::encode_double_quoted_attribute(rt);
            format!(
                r#"<p class="mt-4"><a href="{}" class="text-blue-600 hover:text-blue-700 underline">元のページに戻る</a></p>"#,
                escaped_url
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ゲストアクセス - {}</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="w-full max-w-md bg-white rounded-lg shadow-md p-6">
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h1 class="text-2xl font-bold text-blue-900 mb-2">ゲストアクセス</h1>
                <p class="text-blue-800">このセッションはゲストトークン経由のアクセスです。</p>
                <p class="text-blue-800 mt-2">アカウント設定はご利用いただけません。</p>
                {}
            </div>
        </div>
    </div>
</body>
</html>"#,
        env!("CARGO_PKG_NAME"),
        back_link
    );

    Html(html)
}

/// GET /me - Redirect to account settings page
pub async fn redirect_to_security(
    auth_user: Option<Extension<AuthUser>>,
    Query(params): Query<MeQuery>,
) -> Response {
    match auth_user {
        Some(_) => {
            let target = build_redirect_target("/settings/security", params.return_to.as_deref());
            Redirect::to(&target).into_response()
        }
        None => {
            let next = if let Some(rt) = params.return_to {
                let me_url = format!("/me?return_to={}", urlencoding::encode(&rt));
                urlencoding::encode(&me_url).to_string()
            } else {
                urlencoding::encode("/me").to_string()
            };
            Redirect::to(&format!("/login?next={}", next)).into_response()
        }
    }
}

/// GET /me/password - Redirect to password change page
pub async fn redirect_to_password(
    auth_user: Option<Extension<AuthUser>>,
    Query(params): Query<MeQuery>,
) -> Response {
    match auth_user {
        Some(_) => {
            let target = build_redirect_target("/settings/security/password", params.return_to.as_deref());
            Redirect::to(&target).into_response()
        }
        None => {
            let next = if let Some(rt) = params.return_to {
                let me_url = format!("/me/password?return_to={}", urlencoding::encode(&rt));
                urlencoding::encode(&me_url).to_string()
            } else {
                urlencoding::encode("/me/password").to_string()
            };
            Redirect::to(&format!("/login?next={}", next)).into_response()
        }
    }
}

/// GET /me/mfa - Redirect to MFA settings page
pub async fn redirect_to_mfa(
    auth_user: Option<Extension<AuthUser>>,
    Query(params): Query<MeQuery>,
) -> Response {
    match auth_user {
        Some(_) => {
            let target = build_redirect_target("/settings/security", params.return_to.as_deref());
            Redirect::to(&target).into_response()
        }
        None => {
            let next = if let Some(rt) = params.return_to {
                let me_url = format!("/me/mfa?return_to={}", urlencoding::encode(&rt));
                urlencoding::encode(&me_url).to_string()
            } else {
                urlencoding::encode("/me/mfa").to_string()
            };
            Redirect::to(&format!("/login?next={}", next)).into_response()
        }
    }
}

/// GET /me/devices - Redirect to device management page
pub async fn redirect_to_devices(
    auth_user: Option<Extension<AuthUser>>,
    Query(params): Query<MeQuery>,
) -> Response {
    match auth_user {
        Some(_) => {
            let target = build_redirect_target("/settings/security", params.return_to.as_deref());
            Redirect::to(&target).into_response()
        }
        None => {
            let next = if let Some(rt) = params.return_to {
                let me_url = format!("/me/devices?return_to={}", urlencoding::encode(&rt));
                urlencoding::encode(&me_url).to_string()
            } else {
                urlencoding::encode("/me/devices").to_string()
            };
            Redirect::to(&format!("/login?next={}", next)).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the reflected-XSS finding: a return_to value
    /// containing a `"` must not be able to break out of the href="..."
    /// attribute via an unescaped quote.
    #[test]
    fn test_render_guest_notice_escapes_double_quote() {
        let malicious = r#"/x" autofocus onfocus="alert(1)"#;
        let html = render_guest_notice(Some(malicious)).0;

        assert!(
            !html.contains(r#"" autofocus"#),
            "double-quote must be escaped, got: {html}"
        );
    }

    #[test]
    fn test_validate_return_to_valid_path() {
        assert_eq!(validate_return_to("/dashboard"), Some("/dashboard".to_string()));
        assert_eq!(validate_return_to("/app/page"), Some("/app/page".to_string()));
        assert_eq!(validate_return_to("/"), Some("/".to_string()));
    }

    #[test]
    fn test_validate_return_to_rejects_protocol_relative() {
        assert_eq!(validate_return_to("//evil.com"), None);
        assert_eq!(validate_return_to("//evil.com/path"), None);
    }

    #[test]
    fn test_validate_return_to_rejects_absolute_urls() {
        assert_eq!(validate_return_to("https://evil.com"), None);
        assert_eq!(validate_return_to("http://evil.com"), None);
        assert_eq!(validate_return_to("javascript:alert(1)"), None);
    }

    #[test]
    fn test_validate_return_to_rejects_backslashes() {
        assert_eq!(validate_return_to("/path\\..\\etc"), None);
    }

    #[test]
    fn test_build_redirect_target_with_valid_return_to() {
        let target = build_redirect_target("/settings/security", Some("/dashboard"));
        assert!(target.contains("/settings/security?return_to=%2Fdashboard"));
    }

    #[test]
    fn test_build_redirect_target_without_return_to() {
        let target = build_redirect_target("/settings/security", None);
        assert_eq!(target, "/settings/security");
    }

    #[test]
    fn test_build_redirect_target_with_malicious_return_to() {
        let target = build_redirect_target("/settings/security", Some("https://evil.com"));
        assert_eq!(target, "/settings/security");
    }
}
