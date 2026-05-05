use axum::response::Html;

pub fn render_consent_screen(
    client_name: &str,
    scopes: &[String],
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> Html<String> {
    let scopes_html = scopes
        .iter()
        .map(|s| format!("<li><code>{}</code></li>", s))
        .collect::<Vec<_>>()
        .join("\n");

    let mut hidden_inputs = format!(
        r#"
        <input type="hidden" name="client_id" value="{client_id}">
        <input type="hidden" name="redirect_uri" value="{redirect_uri}">
        <input type="hidden" name="state" value="{state}">
        <input type="hidden" name="scopes" value="{scopes_joined}">
        "#,
        client_id = html_escape::encode_double_quoted_attribute(client_id),
        redirect_uri = html_escape::encode_double_quoted_attribute(redirect_uri),
        state = html_escape::encode_double_quoted_attribute(state),
        scopes_joined = html_escape::encode_double_quoted_attribute(&scopes.join(" ")),
    );

    if let Some(cc) = code_challenge {
        hidden_inputs.push_str(&format!(
            r#"<input type="hidden" name="code_challenge" value="{}">"#,
            html_escape::encode_double_quoted_attribute(cc)
        ));
    }
    if let Some(ccm) = code_challenge_method {
        hidden_inputs.push_str(&format!(
            r#"<input type="hidden" name="code_challenge_method" value="{}">"#,
            html_escape::encode_double_quoted_attribute(ccm)
        ));
    }

    let page = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize {}</title>
    <style>
        :root {{
            --bg-color: #121212;
            --surface-color: #1e1e1e;
            --text-color: #e0e0e0;
            --primary-color: #bb86fc;
            --primary-hover: #9965f4;
            --danger-color: #cf6679;
            --border-radius: 8px;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }}
        .card {{
            background-color: var(--surface-color);
            padding: 2rem;
            border-radius: var(--border-radius);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            max-width: 400px;
            width: 100%;
        }}
        h1 {{
            margin-top: 0;
            font-size: 1.5rem;
            text-align: center;
        }}
        .scopes {{
            background-color: rgba(255, 255, 255, 0.05);
            padding: 1rem;
            border-radius: var(--border-radius);
            margin: 1.5rem 0;
        }}
        ul {{
            margin: 0;
            padding-left: 1.5rem;
        }}
        li {{
            margin-bottom: 0.5rem;
        }}
        code {{
            background-color: rgba(255, 255, 255, 0.1);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .actions {{
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
        }}
        button {{
            flex: 1;
            padding: 0.75rem;
            border: none;
            border-radius: var(--border-radius);
            font-size: 1rem;
            font-weight: bold;
            cursor: pointer;
            transition: opacity 0.2s;
        }}
        button:hover {{
            opacity: 0.9;
        }}
        .btn-approve {{
            background-color: var(--primary-color);
            color: #000;
        }}
        .btn-deny {{
            background-color: transparent;
            color: var(--danger-color);
            border: 1px solid var(--danger-color);
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Authorize <strong>{client_name}</strong></h1>
        <p>This application is requesting access to your Trust Gateway account. It wants permission to:</p>
        
        <div class="scopes">
            <ul>
                {scopes_html}
            </ul>
        </div>

        <form action="/auth/authorize/consent" method="POST">
            {hidden_inputs}
            <div class="actions">
                <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
                <button type="submit" name="action" value="approve" class="btn-approve">Approve</button>
            </div>
        </form>
    </div>
</body>
</html>
"#,
        html_escape::encode_text(client_name),
        client_name = html_escape::encode_text(client_name),
        scopes_html = scopes_html,
        hidden_inputs = hidden_inputs
    );

    Html(page)
}
