// Shared by the hosted pages: a provider sign-in redirect is followed only to the provider's declared
// HTTPS authorization origin; anything else is refused and nothing is opened.
export function signInTarget(authorizationUrl, expectedOrigin) {
  let target;
  try { target = new URL(authorizationUrl); } catch { target = null; }
  if (!target || target.protocol !== 'https:' || typeof expectedOrigin !== 'string' || target.origin !== expectedOrigin) throw new Error('Unexpected sign-in destination. Nothing was opened.');
  return target.href;
}
