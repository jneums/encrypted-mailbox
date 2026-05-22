# 📬 Encrypted Mailbox

A dead-drop encrypted messaging MCP server on the Internet Computer. Send encrypted messages to any principal — no key exchange, no registration, no setup.

Uses **vetKey identity-based encryption (IBE)** so that only the intended recipient can ever read the message. Not even the subnet nodes can see your plaintext.

## How it works

1. **Sender** calls `send_message` with recipient's principal, subject, and body
2. **Canister** derives the recipient's IBE encryption key via vetKD and encrypts the body
3. **Ciphertext** is stored in the recipient's inbox (subject stays plaintext for listing)
4. **Recipient** calls `read_message` — canister derives their decryption key and returns plaintext
5. Messages can be listed (`get_inbox`), counted (`get_inbox_count`), and deleted (`delete_message`)

## Tools

| Tool | Description |
|------|-------------|
| `send_message` | Send an encrypted message to any principal on ICP |
| `get_inbox` | List messages with metadata (no bodies) |
| `read_message` | Decrypt and read a specific message |
| `delete_message` | Delete a message from your inbox |
| `get_inbox_count` | Quick summary: total and unread counts |

## Security Model

- All message bodies are encrypted at rest using ICP vetKey IBE
- The canister derives a unique encryption key per recipient principal using the vetKD threshold protocol
- No single subnet node ever possesses the decryption key
- Subjects are stored in plaintext for inbox listing convenience
- The canister sees plaintext momentarily during `send_message` (canister-side encryption)

## Canister

- **Canister ID:** `hbdyk-pyaaa-aaaai-ralla-cai`
- **MCP Endpoint:** `https://hbdyk-pyaaa-aaaai-ralla-cai.icp0.io/mcp`
- **Namespace:** `io.github.jneums.encrypted-mailbox`

## Development

```bash
# Install dependencies
mops install
npm install

# Start local replica
dfx start --background

# Deploy locally
dfx deploy

# Run tests (42 tests)
npm test
```

## License

MIT
