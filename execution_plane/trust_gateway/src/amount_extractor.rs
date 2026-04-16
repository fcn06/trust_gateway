// ─────────────────────────────────────────────────────────────
// Amount Extractor — WS5.2
//
// Extracts monetary amount and currency from tool call arguments.
// Enables tiered policy rules (min_amount/max_amount) to activate.
// ─────────────────────────────────────────────────────────────

/// Extracted amount and currency from tool arguments.
#[derive(Debug, Clone)]
pub struct ExtractedAmount {
    pub amount: Option<f64>,
    pub currency: Option<String>,
}

/// Known argument keys that may contain monetary amounts.
const AMOUNT_KEYS: &[&str] = &[
    "amount",
    "refund_amount",
    "total",
    "price",
    "value",
    "cost",
    "payment_amount",
    "charge_amount",
    "transfer_amount",
];

/// Known argument keys that may contain currency codes.
const CURRENCY_KEYS: &[&str] = &[
    "currency",
    "currency_code",
    "iso_currency",
];

/// Extract amount and currency from tool call arguments.
///
/// Tries numeric keys first, then falls back to string parsing
/// (handles "$620", "€350.00", "620 EUR", etc).
pub fn extract_amount(arguments: &serde_json::Value) -> ExtractedAmount {
    let amount = extract_numeric_amount(arguments)
        .or_else(|| extract_string_amount(arguments));

    let currency = extract_currency(arguments);

    ExtractedAmount { amount, currency }
}

/// Try direct numeric extraction from known keys.
fn extract_numeric_amount(args: &serde_json::Value) -> Option<f64> {
    for key in AMOUNT_KEYS {
        if let Some(val) = args.get(*key) {
            // Direct numeric
            if let Some(n) = val.as_f64() {
                return Some(n);
            }
            // Integer
            if let Some(n) = val.as_i64() {
                return Some(n as f64);
            }
        }
    }
    None
}

/// Try parsing amount from string values (e.g. "$620.00", "€350", "620 EUR").
fn extract_string_amount(args: &serde_json::Value) -> Option<f64> {
    for key in AMOUNT_KEYS {
        if let Some(s) = args.get(*key).and_then(|v| v.as_str()) {
            // Strip currency symbols and whitespace, keep digits and dots
            let cleaned: String = s.chars()
                .filter(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(v) = cleaned.parse::<f64>() {
                if v > 0.0 {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Extract currency code from known keys, defaulting to EUR.
fn extract_currency(args: &serde_json::Value) -> Option<String> {
    for key in CURRENCY_KEYS {
        if let Some(s) = args.get(*key).and_then(|v| v.as_str()) {
            let code = s.trim().to_uppercase();
            if code.len() == 3 {
                return Some(code);
            }
        }
    }

    // Try to infer from amount string prefixes
    for key in AMOUNT_KEYS {
        if let Some(s) = args.get(*key).and_then(|v| v.as_str()) {
            if s.starts_with('$') || s.contains("USD") { return Some("USD".to_string()); }
            if s.starts_with('€') || s.contains("EUR") { return Some("EUR".to_string()); }
            if s.starts_with('£') || s.contains("GBP") { return Some("GBP".to_string()); }
        }
    }

    // Default
    Some("EUR".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numeric_extraction() {
        let args = serde_json::json!({"amount": 620.0, "currency": "EUR"});
        let result = extract_amount(&args);
        assert_eq!(result.amount, Some(620.0));
        assert_eq!(result.currency, Some("EUR".to_string()));
    }

    #[test]
    fn test_integer_extraction() {
        let args = serde_json::json!({"refund_amount": 100});
        let result = extract_amount(&args);
        assert_eq!(result.amount, Some(100.0));
    }

    #[test]
    fn test_string_extraction() {
        let args = serde_json::json!({"amount": "€350.00"});
        let result = extract_amount(&args);
        assert_eq!(result.amount, Some(350.0));
        assert_eq!(result.currency, Some("EUR".to_string()));
    }

    #[test]
    fn test_no_amount() {
        let args = serde_json::json!({"query": "hello"});
        let result = extract_amount(&args);
        assert_eq!(result.amount, None);
    }
}
