import type { AuthContext, Permission } from '../types'

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
  }
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
