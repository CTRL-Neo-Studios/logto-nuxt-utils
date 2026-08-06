import type { H3Event } from 'h3'
import { createError } from 'h3'
import type { AuthContext, Permission } from '../../types'
import {
  type AuthRequirements,
  type RequirementResult,
  checkRequirements,
} from '../../shared/requirements'
import { useAuthContext } from './verify'

/**
 * Guards for server routes.
 *
 * All of them funnel through {@link requireUser}, so authorization is decided in
 * exactly one place — the same `checkRequirements` used by the client composable and
 * by abilities.
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
 * Requires an authenticated caller, optionally satisfying `requirements`.
 *
 * With no second argument this is a plain authentication check, so route handlers
 * never need their own `if (!user) throw ...` clause.
 *
 * @example
 * ```ts
 * const ctx = await requireUser(event)
 * const ctx = await requireUser(event, { permissions: ['assessment:edit'] })
 * const ctx = await requireUser(event, { anyPermission: ['a', 'b'], verified: true })
 * ```
 *
 * @throws 401 when unauthenticated, 403 when a requirement is unmet.
 */
export async function requireUser(
  event: H3Event,
  requirements?: AuthRequirements,
): Promise<AuthContext> {
  const ctx = await useAuthContext(event)
  const result = checkRequirements(ctx, requirements)

  if (!result.ok) throw toHttpError(result)

  return ctx
}

/**
 * Requires the caller to hold *every* listed permission.
 *
 * Sugar for `requireUser(event, { permissions })`.
 *
 * @throws 401 when unauthenticated, 403 when any permission is missing.
 */
export async function requirePermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<AuthContext> {
  return requireUser(event, { permissions })
}

/**
 * Requires the caller to hold *at least one* of the listed permissions.
 *
 * Sugar for `requireUser(event, { anyPermission })`.
 *
 * @throws 401 when unauthenticated, 403 when none are held.
 */
export async function requireAnyPermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<AuthContext> {
  return requireUser(event, { anyPermission: permissions })
}

/**
 * Requires the caller to hold at least one of the listed roles.
 *
 * Sugar for `requireUser(event, { roles })`. Prefer {@link requirePermission}: roles
 * arrive via the ID token, so a bearer caller normally carries none, and Logto role
 * names are mutable display strings. A role is a bundle of permissions, so checking
 * permissions tests the same thing more durably.
 *
 * @throws 401 when unauthenticated, 403 when no role matches.
 */
export async function requireRole(
  event: H3Event,
  ...roles: string[]
): Promise<AuthContext> {
  return requireUser(event, { roles })
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
