const MAX_SECRET_LENGTH = 51200; // 50 KB
const PUBLIC_URL = window.location.origin;

let unlockedPassphrase = null;

// Generate cryptographically secure random ID
async function generateSecureId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate random IV for AES-GCM
function generateIV() {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return iv;
}

// Generate random AES-GCM key
async function generateEncryptionKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // exportable
    ['encrypt', 'decrypt']
  );
}

// Encrypt secret using AES-GCM
async function encryptSecret(secret, key) {
  const iv = generateIV();
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  // Return IV + ciphertext combined
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv);
  result.set(new Uint8Array(ciphertext), iv.length);

  return result;
}

// Convert bytes to base64
function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Export key to base64 for URL
async function keyToBase64(key) {
  const exported = await crypto.subtle.exportKey('raw', key);
  return bytesToBase64(new Uint8Array(exported));
}

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

// Update character count
function updateCharCount() {
  const secret = document.getElementById('secret');
  const count = document.getElementById('char-count');
  const encoded = new TextEncoder().encode(secret.value);
  count.textContent = encoded.length;

  if (encoded.length > MAX_SECRET_LENGTH) {
    secret.classList.add('error');
    document.getElementById('submit-btn').disabled = true;
  } else {
    secret.classList.remove('error');
    document.getElementById('submit-btn').disabled = false;
  }
}

// Format expiry time
function formatExpiryTime(seconds) {
  const date = new Date(Date.now() + seconds * 1000);
  return date.toLocaleString();
}

// Show error message
function showError(message) {
  const alert = document.getElementById('error-alert');
  alert.textContent = message;
  alert.classList.remove('hidden');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Clear error message
function clearError() {
  const alert = document.getElementById('error-alert');
  alert.classList.add('hidden');
}

// Show passphrase error
function showPassphraseError(message) {
  const errorEl = document.getElementById('passphrase-error');
  errorEl.textContent = message;
  errorEl.classList.remove('hidden');
}

// Clear passphrase error
function clearPassphraseError() {
  const errorEl = document.getElementById('passphrase-error');
  errorEl.classList.add('hidden');
}

// Unlock gate
async function unlockGate() {
  const input = document.getElementById('passphrase-input');
  const passphrase = input.value.trim();

  if (!passphrase) {
    showPassphraseError('Enter a passphrase');
    return;
  }

  clearPassphraseError();

  try {
    const response = await fetch('/api/verify-passphrase', {
      method: 'POST',
      headers: {
        'X-Hush-Passphrase': passphrase
      }
    });

    if (response.status === 401) {
      showPassphraseError('Wrong passphrase');
      input.value = '';
      input.focus();
      return;
    }

    if (response.status >= 500) {
      showPassphraseError('Server error, try again');
      return;
    }

    // Any status other than 401/5xx means passphrase was accepted
    unlockedPassphrase = passphrase;
    document.getElementById('passphrase-gate').classList.add('hidden');
    document.getElementById('create-form').classList.remove('hidden');
    document.getElementById('secret').focus();
  } catch (err) {
    showPassphraseError('Connection error');
  }
}

// Handle form submission
document.getElementById('create-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearError();

  const title = document.getElementById('title').value.trim() || '(Untitled)';
  const secret = document.getElementById('secret').value;
  const expiry = parseInt(document.getElementById('expiry').value);
  const maxViews = parseInt(document.getElementById('max-views').value);

  // Validate
  const encoded = new TextEncoder().encode(secret);
  if (encoded.length === 0) {
    showError('Secret cannot be empty.');
    return;
  }
  if (encoded.length > MAX_SECRET_LENGTH) {
    showError(`Secret exceeds maximum size of ${MAX_SECRET_LENGTH} bytes.`);
    return;
  }
  if (expiry > 604800) {
    showError('Expiry cannot exceed 7 days.');
    return;
  }

  try {
    // Disable submit button and show spinner
    const submitBtn = document.getElementById('submit-btn');
    const submitBtnText = document.getElementById('submit-btn-text');
    const submitSpinner = document.getElementById('submit-spinner');
    submitBtn.disabled = true;
    submitSpinner.classList.remove('hidden');
    submitBtnText.textContent = 'Creating...';

    // Generate encryption key and ID
    const key = await generateEncryptionKey();
    const id = await generateSecureId();

    // Encrypt secret and title (separate IVs — never reuse an IV with the same key)
    const encryptedPayload = await encryptSecret(secret, key);
    const encryptedTitle = await encryptSecret(title, key);

    // Convert to base64 for transmission
    const payload = bytesToBase64(encryptedPayload);
    const encryptedTitleB64 = bytesToBase64(encryptedTitle);

    // Send to server
    const response = await fetch('/api/create', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Hush-Passphrase': unlockedPassphrase
      },
      body: JSON.stringify({
        id,
        payload,
        title: encryptedTitleB64,
        expiry,
        maxViews
      })
    });

    if (!response.ok) {
      const error = await response.text();
      showError(`Server error: ${error}`);
      submitBtn.disabled = false;
      submitSpinner.classList.add('hidden');
      submitBtnText.textContent = 'Create Secret';
      return;
    }

    // Get encryption key as base64 for URL
    const keyB64 = await keyToBase64(key);

    // Build share URL with key in fragment (URL-encoded for iOS Safari compatibility)
    const shareUrl = `${PUBLIC_URL}/s/${id}#${encodeURIComponent(keyB64)}`;

    // Show result
    document.getElementById('main-view').classList.add('hidden');
    document.getElementById('result-view').classList.remove('hidden');
    document.getElementById('share-url').value = shareUrl;
    document.getElementById('expiry-time').textContent = formatExpiryTime(expiry);

    if (maxViews > 0) {
      document.getElementById('view-limit-text').textContent =
        `This secret can be viewed ${maxViews} time${maxViews > 1 ? 's' : ''}.`;
      document.getElementById('view-limit-note').classList.remove('hidden');
    }

    submitBtn.disabled = false;
    submitSpinner.classList.add('hidden');
    submitBtnText.textContent = 'Create Secret';
  } catch (err) {
    console.error(err);
    showError(`Encryption failed: ${err.message}`);
    submitBtn.disabled = false;
    submitSpinner.classList.add('hidden');
    submitBtnText.textContent = 'Create Secret';
  }
});

// Select share URL on click
document.getElementById('share-url').addEventListener('click', (e) => {
  e.target.select();
});

// Copy URL to clipboard
document.getElementById('copy-btn').addEventListener('click', async () => {
  const url = document.getElementById('share-url');
  try {
    await navigator.clipboard.writeText(url.value);
    const btn = document.getElementById('copy-btn');
    const original = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => {
      btn.textContent = original;
    }, 2000);
  } catch (err) {
    alert('Failed to copy. Please copy manually.');
  }
});

// Create another secret
document.getElementById('new-secret-btn').addEventListener('click', () => {
  document.getElementById('create-form').reset();
  document.getElementById('main-view').classList.remove('hidden');
  document.getElementById('result-view').classList.add('hidden');
  document.getElementById('view-limit-note').classList.add('hidden');
  updateCharCount();
});

// Track character count on input
document.getElementById('secret').addEventListener('input', updateCharCount);

// Legal modal
const legalModal = document.getElementById('legal-modal');
const openLegalBtn = document.getElementById('open-legal');
const closeLegalBtn = document.getElementById('close-legal');

openLegalBtn.addEventListener('click', () => {
  legalModal.classList.remove('hidden');
});

closeLegalBtn.addEventListener('click', () => {
  legalModal.classList.add('hidden');
});

legalModal.addEventListener('click', (e) => {
  if (e.target === legalModal) {
    legalModal.classList.add('hidden');
  }
});

// Passphrase gate
document.getElementById('unlock-btn').addEventListener('click', unlockGate);

document.getElementById('passphrase-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    unlockGate();
  }
});

// Custom dropdown functionality
const DROPDOWN_MARGIN = 8; // gap kept clear from the viewport edge
const DROPDOWN_MAX_HEIGHT = 240; // fixed max height, enables scroll if needed
const SCROLL_TOLERANCE = 20; // px of slack before triggering overflow

function initDropdown(triggerId, menuId, inputId) {
  const trigger = document.getElementById(triggerId);
  const menu = document.getElementById(menuId);
  const items = menu.querySelectorAll('.dropdown-item');
  const input = document.getElementById(inputId);

  function positionMenu() {
    const triggerRect = trigger.getBoundingClientRect();
    const contentHeight = menu.scrollHeight;
    const spaceBelow = window.innerHeight - triggerRect.bottom - DROPDOWN_MARGIN;
    const spaceAbove = triggerRect.top - DROPDOWN_MARGIN;

    const fitsBelow = contentHeight <= spaceBelow + SCROLL_TOLERANCE;
    const dropUp = !fitsBelow && spaceAbove > spaceBelow;

    menu.classList.toggle('drop-up', dropUp);
    const available = dropUp ? spaceAbove : spaceBelow;
    menu.style.maxHeight = menu.classList.contains('open')
      ? `${Math.max(0, Math.min(DROPDOWN_MAX_HEIGHT, available))}px`
      : '0px';
  }

  function setMenuOpen(open) {
    menu.classList.toggle('open', open);
    trigger.classList.toggle('open', open);
    positionMenu();
  }

  trigger.addEventListener('click', () => {
    setMenuOpen(!menu.classList.contains('open'));
  });

  items.forEach(item => {
    item.addEventListener('click', () => {
      items.forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      input.value = item.dataset.value;
      trigger.textContent = item.textContent;
      setMenuOpen(false);
    });
  });

  document.addEventListener('click', (e) => {
    if (!trigger.closest('.custom-dropdown').contains(e.target)) {
      setMenuOpen(false);
    }
  });

  window.addEventListener('resize', () => {
    if (menu.classList.contains('open')) {
      positionMenu();
    }
  });
}

initDropdown('expiry-trigger', 'expiry-menu', 'expiry');
initDropdown('views-trigger', 'views-menu', 'max-views');

// Initialize
updateCharCount();
