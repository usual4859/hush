// Read secret endpoint
// GET /api/read/{id}
// Returns: { payload, title, created, expiry, viewCount, maxViews, expired }
// payload and title are both client-encrypted (base64 IV+ciphertext);
// decryption happens in the browser.
// Increments view count and deletes if view limit reached

export async function onRequest(context) {
  if (context.request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const env = context.env;
    const id = context.params.id;

    // Validate ID format
    if (!id || !/^[a-f0-9]{32}$/.test(id)) {
      return new Response('Not found', { status: 404 });
    }

    // Get rate limit key from request IP (guards against ID brute-force/enumeration)
    const ip = context.request.headers.get('cf-connecting-ip') || 'unknown';
    const rateLimitKey = `ratelimit:read:${ip}`;
    const rateLimitWindow = 3600; // 1 hour
    const maxReadsPerHour = 60;

    const currentCount = await env.HUSH_STORE.get(rateLimitKey);
    const count = currentCount ? parseInt(currentCount) : 0;

    if (count >= maxReadsPerHour) {
      return new Response('Rate limit exceeded', { status: 429 });
    }

    await env.HUSH_STORE.put(
      rateLimitKey,
      String(count + 1),
      { expirationTtl: rateLimitWindow }
    );

    // Fetch secret metadata
    const secretData = await env.HUSH_STORE.get(`secret:${id}`);

    if (!secretData) {
      return new Response(JSON.stringify({ expired: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const metadata = JSON.parse(secretData);
    const now = Math.floor(Date.now() / 1000);

    // Check expiry
    if (now > metadata.expiry) {
      // Delete expired secret
      await env.HUSH_STORE.delete(`secret:${id}`);
      return new Response(JSON.stringify({ expired: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Increment view count (best-effort)
    const newViewCount = (metadata.viewCount || 0) + 1;
    metadata.viewCount = newViewCount;

    // Check if view limit reached
    if (metadata.maxViews > 0 && newViewCount > metadata.maxViews) {
      // Delete when view limit reached (best-effort)
      await env.HUSH_STORE.delete(`secret:${id}`);
      return new Response(JSON.stringify({ expired: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Update metadata with new view count.
    // Cloudflare KV requires expirationTtl >= 60; a secret read in the last
    // minute of its life would otherwise fail this put() and 500 out.
    await env.HUSH_STORE.put(
      `secret:${id}`,
      JSON.stringify(metadata),
      { expirationTtl: Math.max(60, metadata.expiry - now) }
    );

    // Return secret (encrypted payload only - decryption happens in browser)
    return new Response(
      JSON.stringify({
        payload: metadata.payload,
        title: metadata.title || '',
        created: metadata.created,
        expiry: metadata.expiry,
        viewCount: newViewCount,
        maxViews: metadata.maxViews,
        expired: false
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, no-cache, must-revalidate, private',
          'X-Content-Type-Options': 'nosniff'
        }
      }
    );
  } catch (err) {
    console.error('Error reading secret:', err);
    return new Response('Internal server error', { status: 500 });
  }
}
