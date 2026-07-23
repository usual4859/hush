export async function timingSafeCompare(provided, expected) {
  const encoder = new TextEncoder();
  const providedBytes = encoder.encode(provided);
  const expectedBytes = encoder.encode(expected);

  // timingSafeEqual throws on length mismatch instead of returning false,
  // so pad both to the same fixed length first — comparing against a
  // constant-size buffer keeps the operation constant-time regardless of
  // the guessed passphrase's length.
  const compareLength = Math.max(providedBytes.length, expectedBytes.length, 32);
  const providedPadded = new Uint8Array(compareLength);
  const expectedPadded = new Uint8Array(compareLength);
  providedPadded.set(providedBytes);
  expectedPadded.set(expectedBytes);

  const paddedEqual = await crypto.subtle.timingSafeEqual(providedPadded, expectedPadded);
  return paddedEqual && providedBytes.length === expectedBytes.length;
}
