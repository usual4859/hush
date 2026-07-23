// Verify passphrase endpoint
// POST /api/verify-passphrase
// Header: X-Hush-Passphrase
// Returns: 200 if correct, 401 if wrong

import { isTrustedOrigin } from '../_lib/origin.js';
import { timingSafeCompare } from '../_lib/passphrase.js';

export async function onRequest(context) {
  if (context.request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  if (!isTrustedOrigin(context.request, context.env)) {
    return new Response('Forbidden', { status: 403 });
  }

  if (!context.env.HUSH_CREATE_PASSWORD) {
    console.error('HUSH_CREATE_PASSWORD not configured');
    return new Response(null, { status: 500 });
  }

  const passphrase = context.request.headers.get('X-Hush-Passphrase');
  if (!passphrase || !(await timingSafeCompare(passphrase, context.env.HUSH_CREATE_PASSWORD))) {
    return new Response(null, { status: 401 });
  }

  return new Response(null, { status: 200 });
}
