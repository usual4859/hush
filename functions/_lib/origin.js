// Lightweight CSRF defense for state-changing endpoints.
// Modern browsers attach Origin on every same-origin and cross-origin
// fetch/XHR request whose method isn't GET/HEAD, so this is a reliable
// same-site check without needing session cookies or tokens.
export function isTrustedOrigin(request, env) {
  const allowed = env.PUBLIC_URL;
  if (!allowed) return false; // misconfigured env — fail closed

  const origin = request.headers.get('Origin');
  if (origin) {
    return origin === allowed;
  }

  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      return new URL(referer).origin === new URL(allowed).origin;
    } catch {
      return false;
    }
  }

  // No Origin and no Referer on a state-changing request — reject.
  return false;
}
