// Create secret endpoint
// POST /api/create
// Body: { id, payload, title, expiry, maxViews } — payload and title are both
// client-encrypted (base64 IV+ciphertext); the server never sees plaintext.
// Returns: { id }

import { isTrustedOrigin } from '../_lib/origin.js';
import { timingSafeCompare } from '../_lib/passphrase.js';

export async function onRequest(context) {
  if (context.request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  if (!isTrustedOrigin(context.request, context.env)) {
    return new Response('Forbidden', { status: 403 });
  }

  // Check passphrase
  if (!context.env.HUSH_CREATE_PASSWORD) {
    console.error('HUSH_CREATE_PASSWORD not configured');
    return new Response(JSON.stringify({ error: 'Server misconfigured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const passphrase = context.request.headers.get('X-Hush-Passphrase');
  if (!passphrase || !(await timingSafeCompare(passphrase, context.env.HUSH_CREATE_PASSWORD))) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const env = context.env;
    const body = await context.request.json();

    // Validate request
    if (!body.id || !body.payload || typeof body.expiry !== 'number') {
      return new Response('Invalid request', { status: 400 });
    }

    const { id, payload, title, expiry, maxViews } = body;
    const maxSecretLength = parseInt(env.SECRET_MAX_LENGTH || '51200');
    const maxExpirySeconds = 604800; // 7 days

    // Validate ID format (hex string, 32 chars = 128 bits)
    if (!/^[a-f0-9]{32}$/.test(id)) {
      return new Response('Invalid ID format', { status: 400 });
    }

    // Validate payload (base64 encoded)
    if (typeof payload !== 'string' || payload.length === 0) {
      return new Response('Invalid payload', { status: 400 });
    }

    // Estimate original size (base64 adds ~33% overhead)
    // length * 0.75 gives approximate byte size.
    // The stored payload is AES-GCM(plaintext) + 12-byte IV + 16-byte tag,
    // so allow that fixed 28-byte overhead on top of the plaintext cap —
    // otherwise a plaintext right at the client-side limit gets rejected here.
    const AES_GCM_OVERHEAD_BYTES = 28;
    const estimatedSize = Math.ceil(payload.length * 0.75);
    if (estimatedSize > maxSecretLength + AES_GCM_OVERHEAD_BYTES) {
      return new Response('Payload exceeds maximum size', { status: 413 });
    }

    // Validate expiry
    if (expiry < 60 || expiry > maxExpirySeconds) {
      return new Response('Invalid expiry time', { status: 400 });
    }

    // Validate title (optional, now client-encrypted like the payload — base64 IV+ciphertext, not plaintext)
    const MAX_TITLE_CIPHERTEXT_LENGTH = 1000; // generous cap for base64(IV + AES-GCM(<=100 char title))
    const secretTitle = typeof title === 'string' ? title : '';
    if (secretTitle.length > MAX_TITLE_CIPHERTEXT_LENGTH) {
      return new Response('Title exceeds maximum size', { status: 413 });
    }

    // Validate maxViews (optional, default 0 for unlimited)
    const validMaxViews = [0, 1, 3, 5];
    const viewLimit = typeof maxViews === 'number' && validMaxViews.includes(maxViews) ? maxViews : 0;
    if (typeof maxViews === 'number' && !validMaxViews.includes(maxViews)) {
      return new Response('Invalid maxViews value', { status: 400 });
    }

    // Get rate limit key from request IP
    const ip = context.request.headers.get('cf-connecting-ip') || 'unknown';
    const rateLimitKey = `ratelimit:create:${ip}`;
    const rateLimitWindow = 3600; // 1 hour
    const maxSecretsPerHour = 100;

    // Check rate limit (simple counter in KV)
    const currentCount = await env.HUSH_STORE.get(rateLimitKey);
    const count = currentCount ? parseInt(currentCount) : 0;

    if (count >= maxSecretsPerHour) {
      return new Response('Rate limit exceeded', { status: 429 });
    }

    // Increment rate limit counter
    await env.HUSH_STORE.put(
      rateLimitKey,
      String(count + 1),
      { expirationTtl: rateLimitWindow }
    );

    // Store encrypted secret in KV
    const now = Math.floor(Date.now() / 1000);
    const metadata = {
      payload,           // Base64 encoded (IV + ciphertext)
      title: secretTitle,
      created: now,
      expiry: now + expiry,
      viewCount: 0,
      maxViews: viewLimit
    };

    // Use KV expiration for automatic cleanup
    await env.HUSH_STORE.put(
      `secret:${id}`,
      JSON.stringify(metadata),
      { expirationTtl: expiry }
    );

    return new Response(
      JSON.stringify({ id }),
      {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (err) {
    console.error('Error creating secret:', err);
    return new Response('Internal server error', { status: 500 });
  }
}
