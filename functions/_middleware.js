// Middleware for security headers and SPA routing

export async function onRequest(context) {
  let response = await context.next();

  // Clone response to add headers
  response = new Response(response.body, response);
  addSecurityHeaders(response, context);

  return response;
}

function addSecurityHeaders(response, context) {
  // Security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'no-referrer');
  response.headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  // CSP (only set if not already set by route handler, e.g. functions/s/[id].js's nonce-based policy)
  if (!response.headers.has('Content-Security-Policy')) {
    response.headers.set(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://cloudflareinsights.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    );
  }

  // Cache control: no caching for API, no-store for secrets
  if (context.request.url.includes('/api/') || context.request.url.includes('/s/')) {
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  }
}
