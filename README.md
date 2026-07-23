# Hush

Secure, ephemeral secret text sharing. Encrypt your secrets in the browser before they ever leave your device, then share a link that self-destructs after a set time or after the first view. The server never sees your plaintext.

## Features

- **Browser-based encryption**: AES-256-GCM encryption happens entirely in your browser
- **Zero-knowledge server**: The encryption key is embedded in the URL fragment and never sent to the server
- **Auto-expiry**: Secrets automatically expire after a configurable time (1 hour to 7 days)
- **View limits**: Optionally set a maximum number of views before the secret is destroyed
- **Single-use links**: View limit of 1 creates truly ephemeral secrets
- **Passphrase protected**: Optionally protect secret creation with a server-side passphrase
- **No logs**: Secrets aren't logged or tracked; only stored temporarily in KV

## Security Model

- **End-to-end encryption**: Secrets are encrypted in the browser using AES-256-GCM. The server only stores encrypted blobs
- **Zero-knowledge**: Encryption key shared via URL fragment (`#keyMaterial`) is never sent to the server or in HTTP headers
- **Automatic destruction**: Secrets expire and are deleted from storage after the configured time or view limit is reached
- **No authentication tracking**: Secret access is anonymous — we don't track who views what

## Requirements

- [Cloudflare Account](https://dash.cloudflare.com/sign-up) (free tier works)
- [Node.js](https://nodejs.org/) (v16+)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (`npm install -g wrangler`)

## Deploy

1. Clone this repo
   ```bash
   git clone https://github.com/minoshw/hush.git
   cd hush
   ```

2. Create a Cloudflare KV namespace
   ```bash
   wrangler login
   wrangler kv:namespace create "HUSH_STORE"
   ```

3. Add the KV namespace IDs to `wrangler.toml`
   ```toml
   [[kv_namespaces]]
   binding = "HUSH_STORE"
   id = "YOUR_KV_NAMESPACE_ID"
   preview_id = "YOUR_KV_PREVIEW_NAMESPACE_ID"
   ```

4. Set your passphrase (required to create secrets)
   ```bash
   wrangler secret put HUSH_CREATE_PASSWORD
   ```

5. Set `PUBLIC_URL` in `wrangler.toml` to your domain
   ```toml
   [vars]
   PUBLIC_URL = "https://your-domain.com"
   ```

6. Deploy
   ```bash
   wrangler pages deploy public --project-name hush
   ```

Done. Hush is live.

## How It Works

1. **Create**: User enters a secret, sets expiry time and view limit
2. **Encrypt**: The browser generates an AES-256 key, encrypts the secret, and generates a random ID
3. **Store**: Encrypted secret is sent to server and stored in Cloudflare KV
4. **Share**: URL is generated with the ID in the path and encryption key in the fragment
5. **Retrieve**: Recipient visits URL; browser decrypts using key from fragment (server never sees it)
6. **Destroy**: Secret is deleted after expiry time or when view limit is reached

## API Endpoints

- `POST /api/create` — Create a new secret (requires `X-Hush-Passphrase` header)
- `GET /api/read/[id]` — Retrieve encrypted secret
- `POST /api/verify-passphrase` — Verify creation passphrase
- `POST /api/report/[id]` — Report a secret as harmful

## License

MIT License - see LICENSE file for details
