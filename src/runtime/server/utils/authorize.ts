import type { H3Event } from 'h3'
import { createError } from 'h3'
import type { Permission } from '../../types'
import {
  type AuthRequirements,
  type RequirementResult,
  checkRequirements,
} from '../../shared/requirements'
import type { ServerLogtoUserClaims } from './logto'
import { useAuthContext } from './verify'

/**
 * Guards for server routes.
 *
 * All of them funnel through {@link requireLogtoUser}, so authorization is decided in
 * exactly one place — the same `checkRequirements` used by the client composable and
 * by abilities.
 *
 * Each returns the **Logto user claims**, matching `useServerLogtoUser(event)` but
 * non-nullable, since the guard has already established there is a user. Permissions
 * are deliberately *not* on that object — they live in an access token's `scope`
 * claim, never in the ID token — so a handler needing them calls
 * `useAuthContext(event)`, which is memoised per request and therefore free after a
 * guard has run.
 *
 * Failures throw an H3 error carrying machine-readable `data`, so a client can
 * discover *which* requirement was unmet instead of just seeing "Forbidden", and can
 * distinguish 401 (sign in) from 403 (not permitted).
 */

function toHttpError(result: Extract<RequirementResult, { ok: false }>) {
  return createError({
    status: result.statusCode,
    statusText: result.statusCode === 401 ? 'Unauthorized' : 'Forbidden',
    // The detail goes in `message`, not `statusText`: h3 strips characters such as `:`
    // from a status text and warns when one is used for a long description — and these
    // messages name permissions like `assessment:edit`.
    message: result.message,
    data: {
      failed: result.failed,
      required: result.required,
      held: result.held,
    },
  })
}

/**
 * Requires an authenticated caller, optionally satisfying `requirements`, and
 * returns their Logto claims.
 *
 * With no second argument this is a plain authentication check, so route handlers
 * never need their own `if (!user) throw ...` clause.
 *
 * The returned claims are `sub`, `email`, `name`, `roles` and friends — the same
 * shape `useServerLogtoUser(event)` yields, but never `undefined`. For a **session**
 * caller these are ID-token claims read from the cookie; for a **bearer** caller they
 * are the verified access-token payload, which carries `sub` and `scope` but normally
 * no profile claims. Read anything permission-related from `useAuthContext(event)`
 * instead.
 *
 * @example
 * ```ts
 * const user = await requireLogtoUser(event)
 * const user = await requireLogtoUser(event, { permissions: ['assessment:edit'] })
 *
 * // Permissions are not ID-token claims, so read them from the context:
 * const { scopes } = await useAuthContext(event)
 * ```
 *
 * @throws 401 when unauthenticated, 403 when a requirement is unmet.
 */
export async function requireLogtoUser(
  event: H3Event,
  requirements?: AuthRequirements,
): Promise<ServerLogtoUserClaims> {
  const ctx = await useAuthContext(event)
  const result = checkRequirements(ctx, requirements)

  if (!result.ok) throw toHttpError(result)

  // `claims` is populated from `useServerLogtoUser` for a session and from the
  // verified JWT payload for a bearer token, so it is present whenever the context
  // is authenticated. Missing here means Logto reported an authenticated session
  // whose ID token could not be decoded — a server fault, not an auth failure, and
  // returning `undefined` would push a null check onto every call site for a case
  // the guard just ruled out.
  if (!ctx.claims) {
    throw createError({
      status: 500,
      statusText: 'Internal Server Error',
      message: 'Authenticated caller has no readable Logto claims.',
    })
  }

  // The claims travel through `AuthContext` as an index-signature record so the
  // shared types stay free of `@logto/node`. Narrowing back is safe: both producers
  // assign exactly this shape.
  return ctx.claims as ServerLogtoUserClaims
}

/**
 * Requires the caller to hold *every* listed permission.
 *
 * Sugar for `requireLogtoUser(event, { permissions })`.
 *
 * @throws 401 when unauthenticated, 403 when any permission is missing.
 */
export async function requirePermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<ServerLogtoUserClaims> {
  return requireLogtoUser(event, { permissions })
}

/**
 * Requires the caller to hold *at least one* of the listed permissions.
 *
 * Sugar for `requireLogtoUser(event, { anyPermission })`.
 *
 * @throws 401 when unauthenticated, 403 when none are held.
 */
export async function requireAnyPermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<ServerLogtoUserClaims> {
  return requireLogtoUser(event, { anyPermission: permissions })
}

/**
 * Requires the caller to hold at least one of the listed roles.
 *
 * Sugar for `requireLogtoUser(event, { roles })`. Prefer {@link requirePermission}:
 * roles arrive via the ID token, so a bearer caller normally carries none, and Logto
 * role names are mutable display strings. A role is a bundle of permissions, so
 * checking permissions tests the same thing more durably.
 *
 * @throws 401 when unauthenticated, 403 when no role matches.
 */
export async function requireRole(
  event: H3Event,
  ...roles: string[]
): Promise<ServerLogtoUserClaims> {
  return requireLogtoUser(event, { roles })
}

/**
 * Non-throwing requirements check, for branching rather than gating.
 *
 * @example
 * ```ts
 * const detailed = await meetsRequirements(event, { permissions: ['assessment:edit'] })
 *   ? await withDrafts()
 *   : await publishedOnly()
 * ```
 */
export async function meetsRequirements(
  event: H3Event,
  requirements?: AuthRequirements,
): Promise<boolean> {
  return checkRequirements(await useAuthContext(event), requirements).ok
}

/** Non-throwing check that the caller holds every listed permission. */
export async function hasPermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<boolean> {
  return meetsRequirements(event, { permissions })
}
