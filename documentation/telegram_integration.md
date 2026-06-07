
# Telegram Integration & Secure Linking

The Trust Gateway allows you to link your decentralized identity to a Telegram account. This enables mobile notifications for high-risk actions and allows you to approve or deny requests directly from your chat app.

## 1. Security Overview

Even though Telegram is a public messaging platform, the Trust Gateway maintains a **Zero-Trust** posture:

*   **Whitelist-Only**: Only Telegram accounts that have been explicitly linked to a system identity can interact with the bot.
*   **Encapsulated Governance**: Telegram is treated purely as a **transport layer**. Every message is normalized and must clear the same **Policy Engine** (TOML rules) as any other channel.
*   **Identity Injection**: Every action originating from Telegram is cryptographically bound to your SSI identity (DID) before execution, ensuring full auditability.

## 2. Setting Up the Bot

To enable Telegram support, you need to configure your bot token in the environment:

1.  Create a bot via [@BotFather](https://t.me/botfather) and get your **Bot Token**.
2.  Set the following in your `.env`:
    ```bash
    TELEGRAM_BOT_TOKEN="your_token_here"
    TELEGRAM_BOT_ENABLED="true"
    ```
3.  Restart the services.

## 3. Secure Linking Flow (The 6-Digit OTP)

To prevent unauthorized linking (identity spoofing), the gateway uses a hardened **One-Time Password (OTP)** mechanism:

### Step 1: Generate Code
Log in to the **Governance Portal** (`http://localhost:8080`) and navigate to **Settings > Telegram Linking**. Click **Generate Code**.

### Step 2: 6-Digit OTP
The portal will display a unique **6-digit numeric code** (e.g., `823 419`).
> [!IMPORTANT]
> This code is only valid for **3 minutes**.

### Step 3: Link on Telegram
Open your bot on Telegram and send:
`/start <your_code>` (e.g., `/start 823419`)

## 4. Anti-Brute-Force Protections

The linking flow is protected by two independent layers of rate limiting:

1.  **Per-Code Limit**: Each 6-digit code allows only **3 failed attempts**. On the 4th error, the code is instantly destroyed.
2.  **Per-User Limit**: Each Telegram account is limited to **10 total attempts** every 30 minutes. This prevents attackers from trying many different codes from a single account.

## 5. Mobile Approvals

Once linked, whenever an agent proposes an action that requires approval (based on your `policy.toml`), you will receive a push notification on Telegram:

*   **Inspect**: Review the action name, arguments, and risk level.
*   **Decision**: Click the **Approve** or **Deny** button directly in the chat.
*   **Execution**: Upon approval, the gateway issues a one-time execution grant and dispatches the tool call.

---

> [!TIP]
> This bridge allows you to maintain the security of a private node while gaining the convenience of mobile management. Your private keys never leave the secure vault; the Telegram bot only acts as a secure messenger for your intent.
