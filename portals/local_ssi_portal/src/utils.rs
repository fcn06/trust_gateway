//! Utility functions for the SSI portal.

use web_sys::{window, HtmlDocument};
use wasm_bindgen::JsCast;

/// Get a cookie value by name
pub fn get_cookie(name: &str) -> Option<String> {
    if let Some(win) = window() {
        if let Some(doc) = win.document() {
            let doc: HtmlDocument = doc.unchecked_into();
            if let Ok(cookie_str) = doc.cookie() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if cookie.starts_with(name) && cookie.contains('=') {
                        return cookie.split('=').nth(1).map(|s| s.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Delete a cookie by name
pub fn delete_cookie(name: &str) {
    if let Some(win) = window() {
        if let Some(doc) = win.document() {
            let doc: HtmlDocument = doc.unchecked_into();
            let _ = doc.set_cookie(&format!("{}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;", name));
        }
    }
}

/// Show an alert with an error message
pub fn alert_error(msg: &str) {
    if let Some(win) = window() {
        let _ = win.alert_with_message(msg);
    }
}
