import type { H3Event } from 'h3'
import { createError, getRequestHeader, isError } from 'h3'
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'
import type { AuthContext } from '../../types'
import {
  contextFromAccessTokenClaims,
  createAnonymousContext,
} from '../../shared/core'
import {
  useLogtoEndpoint,
  useOwnedResources,
  useSessionAuthContext,
} from './auth-context'

/**
 * Cached remote JWKS, keyed by URI.
 *
 * `createRemoteJWKSet` maintains its own key cache with a cooldown between
 * refetches, so reusing one instance across requests matters: constructing one
 * per verification would refetch the key set every time.
 */
const jwkSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function getJwkSet(jwksUri: string) {
  let jwks = jwkSets.get(jwksUri)

  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri))
    jwkSets.set(jwksUri, jwks)
  }

  return jwks
}

/**
 * OIDC issuer and JWKS URI for the configured Logto instance.
 *
 * Built by suffixing the endpoint rather than resolving against its origin, so a
 * Logto deployment hosted under a sub-path keeps working.
 */
function useLogtoOidcUris(event?: H3Event) {
  const endpoint = useLogtoEndpoint(event)
  return { issuer: `${endpoint}/oidc`, jwksUri: `${endpoint}/oidc/jwks` }
}

/** Maps a verified JWT payload onto the shared context shape. */
function contextFromAccessTokenPayload(payload: JWTPayload): AuthContext {
  return contextFromAccessTokenClaims(payload)
}

/**
 * Cryptographically verifies a Logto access token and returns its context.
 *
 * This performs the checks that `@logto/client`'s `getAccessTokenClaims` does
 * **not**. That helper is only a base64 decode with no signature verification,
 * which is safe for a token the server itself fetched over TLS but would be an
 * authentication bypass for a token supplied by a caller.
 *
 * Verified here: signature against Logto's JWKS, `iss` matches this Logto
 * deployment, `aud` matches one of the resources this app **owns**, and `exp` /
 * `nbf` via `jose`. Claims are only read after all of that has passed.
 *
 * Note the audience is drawn from the owned resources only, never from the full set
 * requested at sign-in. Accepting another service's resource as a valid audience
 * would let a token minted for that service be replayed here — and since scope
 * names commonly overlap between services, it could satisfy a permission check it
 * was never intended for.
 *
 * @throws When the token is invalid, expired, or issued for another audience.
 */
export async function verifyAccessToken(
  token: string,
  event?: H3Event,
): Promise<AuthContext> {
  const { issuer, jwksUri } = useLogtoOidcUris(event)
  const audience = useOwnedResources(event)

  if (audience.length === 0) {
    throw createError({
      status: 500,
      statusText: 'Internal Server Error',
      message: 'Cannot verify bearer tokens without a configured API resource. '
        + 'Check that `logtoRbac.resources` is set in nuxt.config.',
    })
  }

  const { payload } = await jwtVerify(token, getJwkSet(jwksUri), { issuer, audience })
  return contextFromAccessTokenPayload(payload)
}

/** Extracts the token from an `Authorization: Bearer <token>` header. */
function readBearerToken(event: H3Event): string | undefined {
  const header = getRequestHeader(event, 'authorization')
  if (!header) return undefined

  const [scheme, ...rest] = header.trim().split(/\s+/u)
  if (scheme?.toLowerCase() !== 'bearer') return undefined

  return rest.join('') || undefined
}

/**
 * Resolves the context from a bearer token, if the request carries one.
 *
 * Returns `undefined` when there is no bearer header at all, but throws 401 when a
 * token is present and invalid: a caller that attempted to authenticate and failed
 * must not be silently downgraded to anonymous.
 */
export async function useBearerAuthContext(event: H3Event): Promise<AuthContext | undefined> {
  const token = readBearerToken(event)
  if (!token) return undefined

  try {
    return await verifyAccessToken(token, event)
  }
  catch (error) {
    if (isError(error)) throw error

    throw createError({
      status: 401,
      statusText: 'Unauthorized',
      message: 'Invalid or expired access token.',
      data: { reason: error instanceof Error ? error.message : String(error) },
    })
  }
}

/**
 * Caches the resolved context per request.
 *
 * `useSessionAuthContext` already memoises the session path, but the bearer path
 * runs `jwtVerify` — a signature check, and potentially a JWKS fetch. Every guard
 * calls this, and a route that both guards and then re-reads `scopes` would
 * otherwise verify the same token twice.
 */
const pendingContexts = new WeakMap<H3Event, Promise<AuthContext>>()

async function buildAuthContext(event: H3Event): Promise<AuthContext> {
  const bearer = await useBearerAuthContext(event)
  if (bearer) return bearer

  try {
    return await useSessionAuthContext(event)
  }
  catch (error) {
    console.warn('[logto-rbac] Failed to resolve session auth context:', error)
    return createAnonymousContext()
  }
}

/**
 * The single entry point for "who is calling this route".
 *
 * Prefers a verified bearer token (a sibling service calling in) and falls back to
 * the Logto session cookie (a browser user), yielding the same shape either way so
 * that one set of guards and abilities covers both.
 *
 * Memoised for the lifetime of the request, so calling it repeatedly — which the
 * guards do — costs one resolution.
 */
export function useAuthContext(event: H3Event): Promise<AuthContext> {
  const pending = pendingContexts.get(event)
  if (pending) return pending

  // Cached before the promise settles so concurrent callers share one resolution.
  // A rejection is not cached: `buildAuthContext` maps session failures to an
  // anonymous context, and a bad bearer token must throw 401 for every caller
  // rather than only the first.
  const promise = buildAuthContext(event).catch((error) => {
    pendingContexts.delete(event)
    throw error
  })

  pendingContexts.set(event, promise)
  return promise
}
