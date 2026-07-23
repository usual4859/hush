// Report/delete secret endpoint
// POST /api/report/{id}
// Deletes a secret without needing the encryption key
// Rate limited to prevent abuse

import { isTrustedOrigin } from '../../_lib/origin.js';

export async function onRequest(context) {
  if (context.request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  if (!isTrustedOrigin(context.request, context.env)) {
    return new Response('Forbidden', { status: 403 });
  }

  try {
    const env = context.env;
    const id = context.params.id;

    // Validate ID format
    if (!id || !/^[a-f0-9]{32}$/.test(id)) {
      return new Response('Not found', { status: 404 });
    }

    // Get rate limit key from request IP
    const ip = context.request.headers.get('cf-connecting-ip') || 'unknown';
    const rateLimitKey = `report-rl:${ip}`;
    const rateLimitWindow = 3600; // 1 hour
    const maxReportsPerHour = 10; // much lower than create limit

    // Check rate limit
    const currentCount = await env.HUSH_STORE.get(rateLimitKey);
    const count = currentCount ? parseInt(currentCount) : 0;

    if (count >= maxReportsPerHour) {
      return new Response('Too many reports', { status: 429 });
    }

    // Increment rate limit counter
    await env.HUSH_STORE.put(
      rateLimitKey,
      String(count + 1),
      { expirationTtl: rateLimitWindow }
    );

    // Delete the secret (we don't know if it exists, but that's OK)
    await env.HUSH_STORE.delete(`secret:${id}`);

    return new Response(
      JSON.stringify({ deleted: true }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (err) {
    console.error('Error reporting secret:', err);
    return new Response('Internal server error', { status: 500 });
  }
}
