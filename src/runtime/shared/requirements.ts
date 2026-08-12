import type { AuthContext, Permission } from '../types'
import {
  ctxHasAll,
  ctxHasAny,
  ctxHasOrganizationRole,
  ctxHasRole,
  ctxMissingPermissions,
  verifiedFromClaims,
} from './core'

/**
 * Declarative authorization requirements.
 *
 * One vocabulary evaluated identically on the server (`requireLogtoUser`), on the
 * client (`useAuthorization().satisfies`) and inside abilities
 * (`definePermissionGates`), so a rule is expressed once and behaves the same
 * everywhere.
 *
 * Everything here is a pure function of the {@link AuthContext}: no Nuxt context, no
 * runtime config, no I/O.
 */

/** What a caller must satisfy. Permissions are the primary mechanism. */
export interface AuthRequirements {
  /**
   * Every one of these permissions must be held.
   *
   * The usual way to express a requirement, and what the shorthand forms elsewhere
   * expand to.
   */
  permissions?: readonly Permission[]
  /** At least one of these permissions must be held. */
  anyPermission?: readonly Permission[]
  /**
   * At least one of these role names must be held, matched exactly.
   *
   * Secondary to permissions. Roles arrive via the ID token, so a bearer caller
   * normally carries none; role names are also mutable display strings in Logto, and
   * a role is ultimately a bundle of permissions. Prefer
   * {@link AuthRequirements.permissions} unless you specifically mean the label.
   */
  roles?: readonly string[]
  /**
   * Membership of an organization, optionally holding one of `roles` within it.
   *
   * With `roles` omitted, only membership is required.
   */
  organization?: {
    id: string
    roles?: readonly string[]
  }
  /**
   * Require a verified email address. Defaults to **`true`**.
   *
   * Reads the `email_verified` claim, rejecting a caller whose claim is explicitly
   * `false`. Pass `verified: false` to allow unverified callers — a deliberate opt-out,
   * so that forgetting to think about it fails closed rather than open.
   *
   * An **absent** claim counts as verified, which is what keeps this default safe:
   * `email_verified` is an ID-token claim, so bearer callers carry none and would
   * otherwise all be rejected. Absence means "no such concept here", not "unverified".
   */
  verified?: boolean
}

/** Which requirement rejected the caller. */
export type RequirementFailure =
  | 'unauthenticated'
  | 'permissions'
  | 'anyPermission'
  | 'roles'
  | 'organization'
  | 'verified'

/** Outcome of {@link checkRequirements}, detailed enough to build an HTTP error from. */
export type RequirementResult =
  | { ok: true }
  | {
    ok: false
    failed: RequirementFailure
    /** 401 when nobody is signed in, 403 when signed in but not permitted. */
    statusCode: 401 | 403
    message: string
    /** What was asked for, for diagnostics. */
    required?: readonly string[]
    /** What the caller actually held, for diagnostics. */
    held?: readonly string[]
  }

/**
 * Whether the caller's email is verified.
 *
 * An absent `email_verified` claim is treated as verified rather than unverified,
 * mirroring the "omit the getter if you have no such concept" behaviour of a
 * configurable role checker. Treating absence as *un*verified would reject every
 * bearer caller, since access tokens do not carry the claim.
 */
export function ctxIsVerified(ctx: AuthContext | null | undefined): boolean {
  // Prefer the claim itself when present: a server-side caller has the real ID token.
  if (ctx?.claims) return verifiedFromClaims(ctx.claims)

  // The browser is deliberately never given `claims`, so it reads the verdict the session
  // endpoint resolved. Absent (a synthetic or legacy context) keeps the historical
  // "nothing to check, so not unverified" behaviour.
  return ctx?.isVerified ?? true
}

/**
 * Evaluates `requirements` against a context, reporting *why* it failed.
 *
 * An absent or unauthenticated context fails immediately with 401 and no further
 * checks, so call sites never need their own null guard.
 *
 * Checks run permissions first, then roles, then organization, then verification, so
 * the reported failure is the most specific and most likely to be actionable.
 *
 * With no requirements, an authenticated caller with a verified email is sufficient:
 * verification is required by default, so a caller whose `email_verified` claim is
 * explicitly `false` is rejected even here. Pass `{ verified: false }` to allow them.
 */
export function checkRequirements(
  ctx: AuthContext | null | undefined,
  requirements: AuthRequirements = {},
): RequirementResult {
  if (!ctx?.isAuthenticated) {
    return {
      ok: false,
      failed: 'unauthenticated',
      statusCode: 401,
      message: 'Authentication required.',
    }
  }

  if (requirements.permissions?.length) {
    const missing = ctxMissingPermissions(ctx, ...requirements.permissions)
    if (missing.length > 0) {
      return {
        ok: false,
        failed: 'permissions',
        statusCode: 403,
        message: `Missing required permission(s): ${missing.join(', ')}.`,
        required: requirements.permissions,
        held: ctx.scopes,
      }
    }
  }

  if (requirements.anyPermission?.length) {
    if (!ctxHasAny(ctx, ...requirements.anyPermission)) {
      return {
        ok: false,
        failed: 'anyPermission',
        statusCode: 403,
        message: `Requires one of the following permission(s): `
          + `${requirements.anyPermission.join(', ')}.`,
        required: requirements.anyPermission,
        held: ctx.scopes,
      }
    }
  }

  if (requirements.roles?.length) {
    if (!ctxHasRole(ctx, ...requirements.roles)) {
      return {
        ok: false,
        failed: 'roles',
        statusCode: 403,
        message: `Requires one of the following role(s): ${requirements.roles.join(', ')}.`,
        required: requirements.roles,
        held: ctx.roles,
      }
    }
  }

  const organization = requirements.organization
  if (organization) {
    const isMember = ctx.organizations.includes(organization.id)
    const hasRole = organization.roles?.length
      ? ctxHasOrganizationRole(ctx, organization.id, ...organization.roles)
      : true

    if (!isMember || !hasRole) {
      return {
        ok: false,
        failed: 'organization',
        statusCode: 403,
        message: organization.roles?.length
          ? `Requires one of the following role(s) in organization `
            + `${organization.id}: ${organization.roles.join(', ')}.`
          : `Requires membership of organization ${organization.id}.`,
        required: organization.roles ?? [organization.id],
        held: ctx.organizationRoles[organization.id] ?? [],
      }
    }
  }

  // Defaults to required: only an explicit `false` waives it, so omitting the field
  // fails closed. Callers whose token carries no `email_verified` claim at all are
  // still admitted — see `ctxIsVerified`.
  if (requirements.verified !== false && !ctxIsVerified(ctx)) {
    return {
      ok: false,
      failed: 'verified',
      statusCode: 403,
      message: 'Requires a verified email address.',
    }
  }

  return { ok: true }
}

/**
 * Boolean form of {@link checkRequirements}, for UI and branching.
 *
 * Safe to call with `null`; it simply returns `false`.
 */
export function ctxSatisfies(
  ctx: AuthContext | null | undefined,
  requirements?: AuthRequirements,
): boolean {
  return checkRequirements(ctx, requirements).ok
}

/** Normalises the shorthand forms accepted wherever requirements are declared. */
export type RequirementsInput = Permission | readonly Permission[] | AuthRequirements

/**
 * Expands a shorthand into full requirements.
 *
 * A bare permission or an array of them means "all of these permissions", which keeps
 * the common case free of any mention of roles.
 */
export function toRequirements(input: RequirementsInput): AuthRequirements {
  if (typeof input === 'string') return { permissions: [input] }
  if (Array.isArray(input)) return { permissions: input as readonly Permission[] }
  return input as AuthRequirements
}

// Re-exported so `ctxHasAll` is reachable from the requirements entry point too,
// keeping "does this context hold these permissions" answerable from one import.
export { ctxHasAll }
