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

/// Delete a cookie by name, attempting to clear it for both the current host and the base domain.
pub fn delete_cookie(name: &str) {
    if let Some(win) = window() {
        if let Some(doc) = win.document() {
            let doc: HtmlDocument = doc.unchecked_into();
            
            // 1. Delete for current host
            let _ = doc.set_cookie(&format!("{}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;", name));
            
            // 2. Attempt to delete for base domain (e.g., .lianxi.io)
            if let Ok(hostname) = win.location().hostname() {
                let parts: Vec<&str> = hostname.split('.').collect();
                if parts.len() >= 2 {
                    let base_domain = parts[parts.len()-2..].join(".");
                    let _ = doc.set_cookie(&format!("{}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=.{};", name, base_domain));
                }
            }
        }
    }
}

/// Show an alert with an error message
pub fn alert_error(msg: &str) {
    if let Some(win) = window() {
        let _ = win.alert_with_message(msg);
    }
}
