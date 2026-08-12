import type { AuthContext, LogtoUserProfile, Permission } from '../types'

/**
 * Framework-free helpers shared by the server guards and the client abilities.
 *
 * Everything here is a pure function so that authorization decisions are made
 * identically on both sides of the wire.
 */

/**
 * Builds a fresh unauthenticated context.
 *
 * A factory rather than a frozen singleton, so callers can never mutate shared
 * state through the nested arrays.
 */
export function createAnonymousContext(): AuthContext {
  return {
    isAuthenticated: false,
    source: 'anonymous',
    roles: [],
    scopes: [],
    organizations: [],
    organizationRoles: {},
    profile: profileFromClaims(undefined),
    // An anonymous caller fails on `unauthenticated` long before verification, so this
    // is inert and avoids implying a second failure reason.
    isVerified: true,
  }
}

/** Reads a claim as a non-empty string, or `null`. */
function readStringClaim(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

/**
 * Normalises token claims into a {@link LogtoUserProfile}.
 *
 * Tolerates any input because claims arrive as `Record<string, unknown>`: a claim of the
 * wrong type is treated as absent rather than trusted or thrown on.
 */
export function profileFromClaims(
  claims: Record<string, unknown> | undefined,
): LogtoUserProfile {
  return {
    sub: readStringClaim(claims?.sub),
    name: readStringClaim(claims?.name),
    username: readStringClaim(claims?.username),
    email: readStringClaim(claims?.email),
    emailVerified: claims?.email_verified === true,
    phoneNumber: readStringClaim(claims?.phone_number),
    phoneNumberVerified: claims?.phone_number_verified === true,
    picture: readStringClaim(claims?.picture),
  }
}

/**
 * Whether these claims satisfy the `verified` requirement.
 *
 * An absent `email_verified` claim counts as verified: it is an ID-token claim, so bearer
 * callers carry none, and treating absence as unverified would reject every
 * service-to-service call. Only an explicit `false` fails.
 */
export function verifiedFromClaims(claims: Record<string, unknown> | undefined): boolean {
  const claim = claims?.email_verified
  return typeof claim === 'boolean' ? claim : true
}

/**
 * Coerces an unknown claim value into a clean array of strings.
 *
 * Necessary because Logto omits claims entirely when their scope was not granted
 * (so `roles` is `undefined`, not `[]`) and returns `null` for unset profile
 * fields.
 */
export function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((entry): entry is string => typeof entry === 'string')
}

/**
 * Splits an OAuth `scope` claim into individual scopes.
 *
 * The claim is a single space-delimited string per RFC 6749; any run of
 * whitespace is tolerated.
 */
export function parseScopeClaim(scope: unknown): string[] {
  if (typeof scope !== 'string') return []
  return scope.split(/\s+/u).filter(Boolean)
}

/**
 * Parses Logto's `organization_roles` claim into a lookup map.
 *
 * Entries are formatted `{organizationId}:{roleName}`. Split on the first colon
 * only, since role names may themselves contain colons.
 */
export function parseOrganizationRoles(value: unknown): Record<string, string[]> {
  const result: Record<string, string[]> = {}

  for (const entry of toStringArray(value)) {
    const separator = entry.indexOf(':')
    if (separator <= 0) continue

    const organizationId = entry.slice(0, separator)
    const role = entry.slice(separator + 1)
    if (!role) continue

    ;(result[organizationId] ??= []).push(role)
  }

  return result
}

/**
 * True when the context holds *every* listed permission.
 *
 * Fails closed for unauthenticated contexts, so an empty permission list can
 * never accidentally authorize a guest.
 */
export function ctxHasAll(
  ctx: AuthContext | null | undefined,
  ...permissions: Permission[]
): boolean {
  if (!ctx?.isAuthenticated) return false
  return permissions.every(permission => ctx.scopes.includes(permission))
}

/** True when the context holds *at least one* of the listed permissions. */
export function ctxHasAny(
  ctx: AuthContext | null | undefined,
  ...permissions: Permission[]
): boolean {
  if (!ctx?.isAuthenticated) return false
  return permissions.some(permission => ctx.scopes.includes(permission))
}

/**
 * True when the context holds at least one of the listed roles.
 *
 * Remember that bearer callers never carry roles, and that Logto role names are
 * mutable display strings; see `AuthContext.roles`.
 */
export function ctxHasRole(
  ctx: AuthContext | null | undefined,
  ...roles: string[]
): boolean {
  if (!ctx?.isAuthenticated) return false
  return roles.some(role => ctx.roles.includes(role))
}

/** The subset of `permissions` the context lacks, for actionable error messages. */
export function ctxMissingPermissions(
  ctx: AuthContext | null | undefined,
  ...permissions: Permission[]
): Permission[] {
  if (!ctx?.isAuthenticated) return [...permissions]
  return permissions.filter(permission => !ctx.scopes.includes(permission))
}

/** True when the context holds one of `roles` within the given organization. */
export function ctxHasOrganizationRole(
  ctx: AuthContext | null | undefined,
  organizationId: string,
  ...roles: string[]
): boolean {
  if (!ctx?.isAuthenticated) return false
  const held = ctx.organizationRoles[organizationId] ?? []
  return roles.some(role => held.includes(role))
}

/**
 * Maps the claims of a **verified** access token onto the shared context shape.
 *
 * Kept here, with the other pure claim helpers, rather than beside the verifier: it
 * is ordinary data normalisation and is far easier to test in isolation. It is
 * deliberately not part of the module's auto-imports, which register only a named
 * subset of this file.
 *
 * Takes a plain record rather than jose's `JWTPayload` so this file stays free of
 * server-only dependencies; `JWTPayload` has a string index signature and so is
 * assignable.
 *
 * Only call this once the token's signature, `iss`, `aud` and `exp` have been
 * checked — nothing here validates anything.
 */
export function contextFromAccessTokenClaims(payload: Record<string, unknown>): AuthContext {
  return {
    isAuthenticated: true,
    source: 'bearer',
    userId: typeof payload.sub === 'string' ? payload.sub : undefined,
    // Logto does not put roles in access tokens by default — `roles` is an ID-token
    // claim — so this is normally empty and bearer callers must be authorized on
    // permissions. It is read rather than hardcoded because a Logto JWT customizer
    // can add a `roles` claim, and discarding one that is present in an
    // already-verified token would be wrong.
    roles: toStringArray(payload.roles),
    scopes: parseScopeClaim(payload.scope),
    organizations: toStringArray(payload.organizations),
    organizationRoles: parseOrganizationRoles(payload.organization_roles),
    claims: payload,
    profile: profileFromClaims(payload),
    isVerified: verifiedFromClaims(payload),
  }
}
