import jwt from 'jsonwebtoken';

// The vulnerable build falls back to a publicly-guessable secret when
// JWT_SECRET is unset. Anyone can mint a valid token with it and impersonate
// any user in any org. This models a real, common production mistake.
export const INSECURE_FALLBACK = 'insecure-dev-fallback';

export function signToken(payload, secret) {
  return jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: '1h' });
}

// Hardened: env-only secret, no fallback. Fails closed.
export function verifyHardened(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}

// Vulnerable: uses the hardcoded fallback when no env secret is present.
export function verifyVulnerable(token, secret) {
  return jwt.verify(token, secret || INSECURE_FALLBACK, { algorithms: ['HS256'] });
}
