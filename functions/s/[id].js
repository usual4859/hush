function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export async function onRequest(context) {
  const id = context.params.id;

  // Validate ID format
  if (!/^[a-f0-9]{32}$/.test(id)) {
    return new Response('Invalid secret ID', { status: 400 });
  }

  const nonce = generateNonce();

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hush — Viewing Secret</title>
  <link rel="icon" type="image/png" sizes="512x512" href="/favicon.png">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="container">
    <header>
      <a href="/" class="brand">
        <svg class="brand-mark" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <polygon points="22.16 9.6 19.16 4.4 15 6.8 15 2 9 2 9 6.8 4.84 4.4 1.84 9.6 6 12 1.84 14.4 4.84 19.6 9 17.2 9 22 15 22 15 17.2 19.16 19.6 22.16 14.4 18 12 22.16 9.6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-miterlimit="10"/>
        </svg>
        <h1>Hush</h1>
      </a>
      <p class="tagline">Secure ephemeral secret sharing</p>
    </header>
    <main>
      <div id="reveal-view">
        <div class="card reveal-card">
          <p>This is a private, self-destructing secret.</p>
          <button type="button" id="reveal-btn" class="btn btn-primary">Reveal Secret</button>
        </div>
      </div>
      <div id="loading-view" class="hidden">
        <p class="loading-text">Decrypting secret...</p>
      </div>
      <div id="secret-view" class="hidden">
        <div class="card">
          <h2 id="secret-title"></h2>
          <div class="secret-content">
            <pre id="secret-text"></pre>
            <button type="button" id="copy-secret-btn" class="btn btn-secondary">Copy Secret</button>
          </div>
          <div class="meta">
            <p id="meta-info"></p>
            <button type="button" id="report-btn" class="report-link" title="Report this secret as harmful or illegal">Report Abuse</button>
          </div>
          <div class="secret-notice">
            <p id="secret-notice-text">This secret was decrypted in your browser. Close this tab when done.</p>
          </div>
        </div>
      </div>
      <div id="error-view" class="hidden">
        <div class="alert alert-error">
          <p id="error-message"></p>
        </div>
      </div>
      <div id="expired-view" class="hidden">
        <div class="alert alert-error">
          <p>This secret has expired or been deleted.</p>
        </div>
      </div>
    </main>
    <footer>
      <p>Encrypted in your browser. We never see your secret.</p>
    </footer>
  </div>
  <div id="report-modal" class="modal hidden">
    <div class="modal-content">
      <button type="button" class="modal-close" id="report-modal-cancel">✕</button>
      <h2>Report Secret</h2>
      <div class="modal-body">
        <p>Report this secret as harmful or illegal? It will be permanently deleted.</p>
      </div>
      <div class="modal-actions">
        <button type="button" id="report-modal-cancel-btn" class="btn btn-secondary">Cancel</button>
        <button type="button" id="report-modal-confirm-btn" class="btn btn-report-confirm">Report &amp; Delete</button>
      </div>
    </div>
  </div>
  <script nonce="${nonce}">
// Import key from base64 (from URL fragment)
async function keyFromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return crypto.subtle.importKey(
    'raw',
    bytes,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );
}

// Decrypt secret using AES-GCM
async function decryptSecret(encryptedData, key) {
  // First 12 bytes are IV, rest is ciphertext
  const iv = encryptedData.slice(0, 12);
  const ciphertext = encryptedData.slice(12);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(plaintext);
}

// Parse ID from URL path
function getSecretId() {
  const path = window.location.pathname;
  const match = path.match(/\\/s\\/([a-f0-9]+)/);
  return match ? match[1] : null;
}

// Get key from URL fragment (handle both encoded and unencoded for backward compatibility)
function getKeyFromFragment() {
  const fragment = window.location.hash.slice(1); // Remove #
  try {
    // Try decoding in case it's URL-encoded (iOS Safari compatibility)
    const decoded = decodeURIComponent(fragment);
    // If decoded version differs from original, use decoded; otherwise use as-is
    return decoded;
  } catch (e) {
    // If decoding fails, use the original fragment
    return fragment;
  }
}

// Show error
function showError(message) {
  document.getElementById('reveal-view').classList.add('hidden');
  document.getElementById('loading-view').classList.add('hidden');
  document.getElementById('secret-view').classList.add('hidden');
  document.getElementById('expired-view').classList.add('hidden');
  document.getElementById('error-view').classList.remove('hidden');
  document.getElementById('error-message').textContent = message;
}

// Show expired
function showExpired() {
  document.getElementById('reveal-view').classList.add('hidden');
  document.getElementById('loading-view').classList.add('hidden');
  document.getElementById('secret-view').classList.add('hidden');
  document.getElementById('error-view').classList.add('hidden');
  document.getElementById('expired-view').classList.remove('hidden');
}

// Format time ago
function timeAgo(date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return seconds + 's ago';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
  return Math.floor(seconds / 86400) + 'd ago';
}

// Load and decrypt secret
async function loadSecret() {
  const id = getSecretId();
  const keyB64 = getKeyFromFragment();

  if (!id || !keyB64) {
    showError('Invalid secret URL.');
    return;
  }

  document.getElementById('reveal-view').classList.add('hidden');
  document.getElementById('loading-view').classList.remove('hidden');

  try {
    // Import key from fragment
    const key = await keyFromBase64(keyB64);

    // Fetch encrypted payload from API
    const response = await fetch('/api/read/' + id);
    if (!response.ok) {
      if (response.status === 404) {
        showExpired();
      } else {
        showError('Server error: ' + response.statusText);
      }
      return;
    }

    const data = await response.json();

    if (data.expired || !data.payload) {
      showExpired();
      return;
    }

    // Decode base64 payload
    const binary = atob(data.payload);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    // Decrypt
    const secret = await decryptSecret(bytes, key);

    // Decrypt title (client-encrypted like the payload, with its own IV)
    let title = '(Untitled)';
    if (data.title) {
      try {
        const titleBinary = atob(data.title);
        const titleBytes = new Uint8Array(titleBinary.length);
        for (let i = 0; i < titleBinary.length; i++) {
          titleBytes[i] = titleBinary.charCodeAt(i);
        }
        title = await decryptSecret(titleBytes, key);
      } catch (err) {
        title = '(Untitled)';
      }
    }

    // Display secret
    document.getElementById('loading-view').classList.add('hidden');
    document.getElementById('secret-view').classList.remove('hidden');
    document.getElementById('secret-title').textContent = title;
    document.getElementById('secret-text').textContent = secret;

    // Show metadata
    const created = new Date(data.created * 1000);
    const viewCount = data.viewCount || 0;
    const maxViews = data.maxViews || 0;

    let metaText = 'Created ' + timeAgo(created);
    if (maxViews > 0) {
      metaText += ' • Views: ' + viewCount + '/' + maxViews;
    }
    document.getElementById('meta-info').textContent = metaText;

    // Update secret notice with remaining views
    if (maxViews > 0) {
      const remainingViews = maxViews - viewCount;
      document.getElementById('secret-notice-text').textContent = 'This secret was decrypted in your browser. ' + remainingViews + ' view' + (remainingViews === 1 ? '' : 's') + ' remaining.';
    }

    // Setup copy button
    document.getElementById('copy-secret-btn').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(secret);
        const btn = document.getElementById('copy-secret-btn');
        const original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = original;
        }, 2000);
      } catch (err) {
        alert('Failed to copy. Please copy manually.');
      }
    });

    // Setup report button
    const reportModal = document.getElementById('report-modal');
    const reportBtn = document.getElementById('report-btn');
    const reportConfirmBtn = document.getElementById('report-modal-confirm-btn');

    reportBtn.addEventListener('click', () => {
      reportModal.classList.remove('hidden');
    });

    document.getElementById('report-modal-cancel').addEventListener('click', () => {
      reportModal.classList.add('hidden');
    });

    document.getElementById('report-modal-cancel-btn').addEventListener('click', () => {
      reportModal.classList.add('hidden');
    });

    reportModal.addEventListener('click', (e) => {
      if (e.target === reportModal) {
        reportModal.classList.add('hidden');
      }
    });

    reportConfirmBtn.addEventListener('click', async () => {
      try {
        reportConfirmBtn.disabled = true;
        reportConfirmBtn.textContent = 'Reporting...';
        const response = await fetch('/api/report/' + id, { method: 'POST' });
        reportModal.classList.add('hidden');
        if (response.ok) {
          showError('Secret has been reported and deleted.');
        } else {
          reportConfirmBtn.disabled = false;
          reportConfirmBtn.textContent = 'Report & Delete';
          showError('Failed to report. Please try again.');
        }
      } catch (err) {
        reportModal.classList.add('hidden');
        reportConfirmBtn.disabled = false;
        reportConfirmBtn.textContent = 'Report & Delete';
        showError('Error reporting secret.');
      }
    });
  } catch (err) {
    console.error(err);
    showError('Decryption failed: ' + err.message);
  }
}

// Require explicit user click before fetching/decrypting.
// Prevents link-preview crawlers (iMessage, WhatsApp, Slack, Teams) that
// execute page JS from silently consuming one-time secrets.
document.getElementById('reveal-btn').addEventListener('click', loadSecret, { once: true });
  </script>
</body>
</html>`;

  const response = new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://static.cloudflareinsights.com; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://cloudflareinsights.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`
    }
  });

  return response;
}
