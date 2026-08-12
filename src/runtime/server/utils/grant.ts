// Type-only, so this module pulls in no runtime dependency of its own: the fingerprint
// is unit-tested by direct import, outside any Nitro or Nuxt context.
import type { ServerLogtoClient } from './logto'

/**
 * The subset of Logto's own session storage this module writes to.
 *
 * Namespaced keys sit alongside `@logto/client`'s `idToken`, `refreshToken`,
 * `accessToken` and `signInSession` entries, which is what makes them encrypted,
 * transmitted and destroyed with the session they describe rather than needing a second
 * cookie of their own.
 */
interface LogtoSessionStorage {
  getItem: (key: string) => Promise<string | null>
  setItem: (key: string, value: string) => Promise<void>
}

/** Warns once when the storage is unreachable, since the condition recurs per request. */
let warnedMissingStorage = false

/**
 * The session storage backing the client, for this module's own bookkeeping.
 *
 * Reached by narrowing rather than assertion because it is *not* part of
 * {@link ServerLogtoClient}: that type is inferred from `@logto/nuxt`'s context
 * augmentation, and `adapter` is an implementation detail of `@logto/client`. It holds
 * the `CookieStorage` that `@logto/nuxt`'s handler constructs, whose `setItem`
 * re-encrypts and re-sends the whole cookie, so a value written here lands on the
 * current response.
 *
 * Returns `undefined` rather than throwing if a future `@logto/client` stops exposing
 * it. What is stored here only makes permission changes propagate *sooner*, so losing it
 * must degrade to the previous reuse-until-expiry behaviour instead of failing every
 * request. This is the module's only reliance on a `@logto/client` internal, so it
 * breaks in exactly one observable place.
 */
function useLogtoSessionStorage(client: ServerLogtoClient): LogtoSessionStorage | undefined {
  const adapter = client && typeof client === 'object' && 'adapter' in client
    ? client.adapter
    : undefined
  const storage = adapter && typeof adapter === 'object' && 'storage' in adapter
    ? adapter.storage
    : undefined

  if (
    storage && typeof storage === 'object'
    && 'getItem' in storage && typeof storage.getItem === 'function'
    && 'setItem' in storage && typeof storage.setItem === 'function'
  ) {
    // Asserted only after both methods are confirmed callable; the signatures
    // themselves are `@logto/client`'s and cannot be checked at runtime.
    return storage as LogtoSessionStorage
  }

  if (!warnedMissingStorage) {
    warnedMissingStorage = true
    console.warn(
      '[logto-rbac] The Logto client no longer exposes `adapter.storage`, so session '
      + 'grant bookkeeping cannot be stored. Permission and role changes will only take '
      + 'effect once the access token expires, as they did before `revalidateAfter` '
      + 'existed, and `needsReauthorization` will always be false. This needs a fix in '
      + '@type32/logto-nuxt-utils.',
    )
  }
}

/**
 * Storage key holding this module's per-session bookkeeping.
 *
 * Written into Logto's own encrypted session storage rather than a cookie of this
 * module's making so it is created, encrypted and destroyed with the session it
 * describes, and namespaced to avoid colliding with `@logto/client`'s own `idToken`,
 * `refreshToken`, `accessToken` and `signInSession` keys.
 */
const GRANT_KEY = 'logtoRbac:grant'

/**
 * What this module remembers about a session between requests.
 *
 * The session cookie records neither when its tokens were obtained nor which
 * permissions were in force when they were granted, and both are needed: the first to
 * bound how long a revoked permission keeps working, the second to notice that a
 * permission was added after the grant was made.
 */
export interface SessionGrant {
  /**
   * `iat` of the ID token this record describes.
   *
   * This is what lets the record be discarded once it stops applying. `signIn` clears
   * only Logto's own token keys (`clearAllTokens`), so the record outlives a
   * re-authorization and would otherwise keep reporting a grant the session no longer
   * has. The stored ID token is replaced either by a refresh grant — which happens
   * inside a request this module is driving, and is recorded as it happens — or by the
   * sign-in callback, which `@logto/nuxt` owns and this module never observes. So an
   * `iat` that moved *between* requests means the session was re-authorized.
   */
  issuedAt: number
  /** Unix seconds at which this session's resource tokens were last fetched. */
  fetchedAt: number
  /** Fingerprint of the permission list in force when the grant was made. */
  fingerprint: string
}

/**
 * Order-insensitive digest of a permission list (FNV-1a, 32-bit, hex).
 *
 * Not cryptographic and deliberately so: the value is only ever compared with one this
 * server wrote, inside an already-encrypted cookie, to answer "is this the same list".
 * A hash rather than the list itself keeps the cookie small — it shares the cookie with
 * the access-token cache, which is bounded by the ~4KB cookie limit.
 */
export function fingerprintPermissions(permissions: readonly string[]): string {
  let hash = 0x811C9DC5

  for (const permission of [...permissions].sort()) {
    for (let index = 0; index < permission.length; index += 1) {
      hash ^= permission.charCodeAt(index)
      hash = Math.imul(hash, 0x01000193)
    }

    // Separator, so ['ab','c'] and ['a','bc'] cannot collide.
    hash ^= 0x1F
    hash = Math.imul(hash, 0x01000193)
  }

  return (hash >>> 0).toString(16)
}

/** Reads the stored bookkeeping, or `undefined` when absent or unreadable. */
export async function readSessionGrant(
  client: ServerLogtoClient,
): Promise<SessionGrant | undefined> {
  const raw = await useLogtoSessionStorage(client)?.getItem(GRANT_KEY)
  if (!raw) return undefined

  let parsed: unknown

  try {
    parsed = JSON.parse(raw)
  }
  catch {
    // This module wrote the value, but a record from an older version, a truncated
    // cookie or a hand-edited one must read as "nothing recorded" rather than throw:
    // the session itself is still valid, and the caller re-adopts it on the spot.
    return undefined
  }

  if (
    parsed && typeof parsed === 'object'
    && 'issuedAt' in parsed && typeof parsed.issuedAt === 'number'
    && 'fetchedAt' in parsed && typeof parsed.fetchedAt === 'number'
    && 'fingerprint' in parsed && typeof parsed.fingerprint === 'string'
  ) {
    return {
      issuedAt: parsed.issuedAt,
      fetchedAt: parsed.fetchedAt,
      fingerprint: parsed.fingerprint,
    }
  }
}

/**
 * Persists the bookkeeping into the session cookie.
 *
 * `setItem` re-encrypts and re-sends the entire cookie, so callers write only when a
 * field actually changed: writing on every request would add an AES-GCM encryption and
 * a `Set-Cookie` header to responses that need neither.
 */
export async function writeSessionGrant(
  client: ServerLogtoClient,
  grant: SessionGrant,
): Promise<void> {
  await useLogtoSessionStorage(client)?.setItem(GRANT_KEY, JSON.stringify(grant))
}
