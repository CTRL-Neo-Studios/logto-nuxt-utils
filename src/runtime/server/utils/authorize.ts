import type { H3Event } from 'h3'
import { createError } from 'h3'
import type { AuthContext, Permission } from '../../types'
import { ctxHasAny, ctxHasRole, ctxMissingPermissions } from '../../shared/core'
import { useAuthContext } from './verify'

/**
 * Guards for server routes.
 *
 * Each resolves the caller once (memoised per request) and throws an H3 error
 * carrying machine-readable `data`, so a client can discover *which* permission
 * was missing instead of just seeing "Forbidden".
 *
 * Permission arguments are typed as {@link Permission}, which resolves to the
 * literal union from your `rbac.config.ts` — a renamed or misspelled permission is
 * a compile error rather than a silent always-deny.
 */

/**
 * Requires an authenticated caller.
 *
 * @throws 401 when the request carries no usable session or bearer token.
 */
export async function requireUser(event: H3Event): Promise<AuthContext> {
  const ctx = await useAuthContext(event)

  if (!ctx.isAuthenticated) {
    throw createError({ statusCode: 401, statusMessage: 'Authentication required.' })
  }

  return ctx
}

/**
 * Requires the caller to hold *every* listed permission.
 *
 * @throws 401 when unauthenticated, 403 when any permission is missing.
 */
export async function requirePermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<AuthContext> {
  const ctx = await requireUser(event)
  const missing = ctxMissingPermissions(ctx, ...permissions)

  if (missing.length > 0) {
    throw createError({
      statusCode: 403,
      statusMessage: `Missing required permission(s): ${missing.join(', ')}.`,
      data: { required: permissions, missing },
    })
  }

  return ctx
}

/**
 * Requires the caller to hold *at least one* of the listed permissions.
 *
 * @throws 401 when unauthenticated, 403 when none are held.
 */
export async function requireAnyPermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<AuthContext> {
  const ctx = await requireUser(event)

  if (!ctxHasAny(ctx, ...permissions)) {
    throw createError({
      statusCode: 403,
      statusMessage: `Requires one of the following permission(s): ${permissions.join(', ')}.`,
      data: { requiredAnyOf: permissions, held: ctx.scopes },
    })
  }

  return ctx
}

/**
 * Requires the caller to hold at least one of the listed roles.
 *
 * Prefer {@link requirePermission} wherever possible. Roles arrive via the ID token,
 * so a bearer caller normally carries none and is rejected unless your access tokens
 * include a `roles` claim through a Logto JWT customizer. Logto role names are also
 * mutable display strings that can be renamed in the console, and a role is just a
 * bundle of permissions — so a permission check tests the same thing more durably.
 *
 * @throws 401 when unauthenticated, 403 when no role matches.
 */
export async function requireRole(
  event: H3Event,
  ...roles: string[]
): Promise<AuthContext> {
  const ctx = await requireUser(event)

  if (!ctxHasRole(ctx, ...roles)) {
    throw createError({
      statusCode: 403,
      statusMessage: `Requires one of the following role(s): ${roles.join(', ')}.`,
      data: { requiredAnyOf: roles, held: ctx.roles },
    })
  }

  return ctx
}

/** Non-throwing permission check, for branching rather than gating. */
export async function hasPermission(
  event: H3Event,
  ...permissions: Permission[]
): Promise<boolean> {
  const ctx = await useAuthContext(event)
  return ctxMissingPermissions(ctx, ...permissions).length === 0
}
