import type { H3Event } from 'h3'
import { createError } from 'h3'
import type { AuthContext } from '../../types'
import {
  createAnonymousContext,
  parseOrganizationRoles,
  parseScopeClaim,
  profileFromClaims,
  toStringArray,
  verifiedFromClaims,
} from '../../shared/core'
import {
  type ServerLogtoClient,
  useServerLogtoClient,
  useServerLogtoUser,
} from './logto'
import { describeLogtoOidcError, formatLogtoOidcError } from '../../shared/diagnostics'
import { useRuntimeConfig } from '#imports'

/**
 * Resources already warned about, so a recurring condition is reported once.
 *
 * Failing to mint a resource token is an expected steady state, not an incident:
 * Logto declines outright when the user holds no permissions on a resource, and a
 * session predating a newly added resource fails every single request until the user
 * signs in again. Logging the full error each time buried one page load under three
 * identical forty-line stack traces.
 *
 * Keyed by resource *and* error code so a genuinely new failure still surfaces. The
 * set is process-lifetime because it exists to keep a dev server's console readable,
 * and the underlying causes are config- or session-shaped rather than transient.
 */
const warnedResourceFailures = new Set<string>()

/** Caches the in-flight context per request so repeated guards cost nothing. */
const pendingContexts = new WeakMap<H3Event, Promise<AuthContext>>()

/**
 * The subset of `runtimeConfig.logto` this module reads.
 *
 * Accessed through an explicit cast because Nuxt generates the type of
 * `runtimeConfig.logto` from whatever the *consuming* app happens to set in its
 * own config, so it cannot be relied on structurally from inside the module.
 */
interface LogtoRuntimeConfigView {
  endpoint?: string
  resources?: string[]
  scopes?: string[]
  fetchUserInfo?: boolean
}

function useLogtoRuntimeConfig(event?: H3Event): LogtoRuntimeConfigView {
  const config = useRuntimeConfig(event) as unknown as Record<string, unknown>
  return (config.logto ?? {}) as LogtoRuntimeConfigView
}

/**
 * The API resources this app owns, as declared in `rbac.config.ts`.
 *
 * Deliberately read from this module's own runtime config rather than from
 * `logto.resources`, which also holds other services' resources so that tokens for
 * them can be obtained. Only the owned list is accepted as an inbound `aud`, and
 * only it contributes permissions — that separation is what prevents a token minted
 * for another service being honoured here.
 */
export function useOwnedResources(event?: H3Event): string[] {
  const config = useRuntimeConfig(event) as unknown as {
    logtoRbac?: { resources?: string[] }
  }
  return config.logtoRbac?.resources ?? []
}

/** Every resource requested at sign-in, owned or not. */
export function useRequestedResources(event?: H3Event): string[] {
  return useLogtoRuntimeConfig(event).resources ?? []
}

/** Base Logto endpoint, with any trailing slashes removed. */
export function useLogtoEndpoint(event?: H3Event): string {
  return String(useLogtoRuntimeConfig(event).endpoint ?? '').replace(/\/+$/u, '')
}

/**
 * Obtains an access token for calling another service.
 *
 * Use this for outbound requests to resources declared in `additionalResources`,
 * passing the result as `Authorization: Bearer <token>`.
 *
 * @throws When `resource` was never requested at sign-in, because Logto cannot mint
 * a token for it and a silent `undefined` would be much harder to diagnose than a
 * typo caught here.
 */
export async function useLogtoAccessToken(
  event: H3Event,
  resource: string,
): Promise<string | undefined> {
  if (!useRequestedResources(event).includes(resource)) {
    throw createError({
      status: 500,
      statusText: 'Internal Server Error',
      message: `"${resource}" is not a configured resource. Add it to `
        + '`logtoRbac.resources` or `logtoRbac.additionalResources`, then sign in again '
        + 'so the refresh token is granted access to it.',
    })
  }

  const client = await useServerLogtoClient(event)
  if (!(await client.isAuthenticated())) return undefined

  try {
    return await client.getAccessToken(resource)
  }
  catch (error) {
    console.warn(`[logto-rbac] Could not obtain an access token for '${resource}':`, error)
    return undefined
  }
}

/**
 * Reads the granted permissions for the current session.
 *
 * Permissions exist *only* in the `scope` claim of a resource-scoped access token,
 * never in the ID token or userinfo response. Logto applies the requested scopes to
 * every resource, and each token carries only the scopes its own resource defines,
 * so the complete permission set is the union across all owned resources.
 *
 * Fetched in parallel, because a cold session needs one refresh-token exchange per
 * resource.
 *
 * Each resource is tolerated individually and simply contributes nothing on
 * failure. With several resources that is the *normal* path rather than an edge
 * case: Logto declines to mint a token for any resource on which the user holds no
 * permissions at all, and `getAccessToken` throws `not_authenticated` once the
 * refresh token is gone. Neither is a server fault, and a user without permissions
 * must receive a clean 403 from the guards rather than a 500.
 */
async function resolveResourceScopes(
  event: H3Event,
  client: ServerLogtoClient,
): Promise<string[]> {
  const resources = useOwnedResources(event)

  if (resources.length === 0) {
    console.warn(
      '[logto-rbac] No owned Logto API resources configured, so no permissions can ever '
      + 'be granted. Check that rbac.config.ts sets `resources`.',
    )
    return []
  }

  const perResource = await Promise.all(resources.map(async (resource) => {
    try {
      const claims = await client.getAccessTokenClaims(resource)
      return parseScopeClaim(claims.scope)
    }
    catch (error) {
      const info = describeLogtoOidcError(error)
      const key = `${resource}@${info?.error ?? 'unknown'}`

      // Report each distinct condition once. The stack trace is deliberately dropped:
      // it points into `@logto/client`'s requester, never at anything the consumer
      // can act on, whereas the hint says exactly what to do.
      if (!warnedResourceFailures.has(key)) {
        warnedResourceFailures.add(key)

        console.warn(
          `[logto-rbac] Could not obtain a '${resource}' access token; contributing no `
          + 'permissions from it.'
          + (info ? `\n${formatLogtoOidcError(info)}\n` : ` ${String(error)}`),
        )
      }

      return []
    }
  }))

  return [...new Set(perResource.flat())]
}

/** Builds the context from the encrypted Logto session cookie. */
async function buildSessionAuthContext(event: H3Event): Promise<AuthContext> {
  const client = await useServerLogtoClient(event)

  if (!(await client.isAuthenticated())) return createAnonymousContext()

  // ID-token claims: free, already decrypted from the session cookie.
  const claims = await useServerLogtoUser(event)
  const scopes = await resolveResourceScopes(event, client)

  return {
    isAuthenticated: true,
    source: 'session',
    userId: claims?.sub,
    roles: toStringArray(claims?.roles),
    scopes,
    organizations: toStringArray(claims?.organizations),
    organizationRoles: parseOrganizationRoles(claims?.organization_roles),
    claims: claims as Record<string, unknown> | undefined,
    profile: profileFromClaims(claims as Record<string, unknown> | undefined),
    isVerified: verifiedFromClaims(claims as Record<string, unknown> | undefined),
  }
}

/**
 * Resolves the calling user's roles and permissions from their session cookie,
 * memoised for the lifetime of the request.
 */
export function useSessionAuthContext(event: H3Event): Promise<AuthContext> {
  const pending = pendingContexts.get(event)
  if (pending) return pending

  const promise = buildSessionAuthContext(event)
  pendingContexts.set(event, promise)
  return promise
}

/**
 * Discards the cached tokens and re-reads the context from Logto.
 *
 * Roles and permissions are a snapshot taken when the token was issued, so
 * changing a user's roles in Logto does not affect an already-issued token (its
 * lifetime is typically one hour). Call this after a role change to make the new
 * grants effective immediately instead of waiting out the TTL.
 *
 * Note this clears every cached access token for the session, not only this
 * resource's.
 */
export async function refreshAuthContext(event: H3Event): Promise<AuthContext> {
  const client = await useServerLogtoClient(event)
  await client.clearAccessToken()
  pendingContexts.delete(event)

  // An explicit refresh is the point at which a previously failing resource may start
  // working, so forget what has been warned about — otherwise a condition that
  // recurs after the refresh would be silently suppressed.
  warnedResourceFailures.clear()

  return useSessionAuthContext(event)
}
