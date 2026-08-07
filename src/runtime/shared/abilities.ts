import {
  allow,
  defineAbility,
  deny,
  normalizeAuthorizationResponse,
  type AuthorizationResponse,
  type BouncerAbility,
} from 'nuxt-authorization/utils'
import type { AuthContext, Permission } from '../types'
import {
  type AuthRequirements,
  type RequirementsInput,
  checkRequirements,
  toRequirements,
} from './requirements'

/**
 * Permission-backed abilities for `nuxt-authorization`.
 *
 * These exist so one authorization vocabulary covers server routes
 * (`authorize(event, gate)`) and templates (`<Can :ability="gate">`) alike, instead
 * of hand-checking scopes in one place and abilities in the other.
 *
 * Every ability produced here is **pre-bound and takes no arguments**, which is what
 * keeps template usage clean: `<Can :ability="gates.viewAssessment">` needs no
 * `:args`. Abilities that depend on a record (ownership checks and the like) are
 * ordinary `defineAbility` calls in your own code, and compose with these via
 * {@link anyOfAbilities} / {@link allOfAbilities}.
 */

/** A zero-argument ability evaluated against the resolved {@link AuthContext}. */
export type PermissionAbility = {
  allowGuest: boolean
  original: (user: AuthContext) => AuthorizationResponse | Promise<AuthorizationResponse>
  execute: (user: AuthContext | null) => AuthorizationResponse | Promise<AuthorizationResponse>
}

/** Any ability that can be evaluated against an auth context. */
type AnyContextAbility = BouncerAbility<AuthContext>

type ContextAuthorizer = (
  user: AuthContext | null,
) => AuthorizationResponse | Promise<AuthorizationResponse>

/**
 * Builds an ability that inspects the auth context itself, including when it is
 * `null`.
 *
 * `allowGuest: true` is essential rather than incidental: with the default,
 * `nuxt-authorization` short-circuits a `null` user into a bare `{authorized:
 * false}` *before* the authorizer runs, which would collapse "not signed in" and
 * "signed in but lacking a permission" into the same 403. Handling the guest case
 * ourselves is what allows a 401 to be reported for the former, matching the server
 * guards (`requireLogtoUser` / `requirePermission`).
 *
 * The cast is confined to this one function: `BouncerAuthorizer` types its first
 * parameter as non-nullable, yet the runtime passes `null` for guests precisely when
 * `allowGuest` is set.
 */
function defineContextAbility(authorizer: ContextAuthorizer): PermissionAbility {
  return defineAbility(
    { allowGuest: true },
    authorizer as unknown as (user: AuthContext) => AuthorizationResponse,
  ) as unknown as PermissionAbility
}

function denyForbidden(message: string): AuthorizationResponse {
  return deny({ statusCode: 403, message })
}

/**
 * The single ability builder: turns declarative requirements into an ability.
 *
 * Delegates to the same `checkRequirements` the server guards use, so a rule behaves
 * identically whether it is enforced by `requireLogtoUser` in a route or by `<Can>` in
 * a template — including the 401-versus-403 distinction.
 */
export function defineRequirementsAbility(requirements: AuthRequirements): PermissionAbility {
  return defineContextAbility((user) => {
    const result = checkRequirements(user, requirements)
    if (result.ok) return allow()

    return deny({ statusCode: result.statusCode, message: result.message })
  })
}

/**
 * An ability requiring **every** listed permission.
 *
 * @example
 * ```ts
 * export const manageAssessment = definePermissionAbility('assessment:edit', 'assessment:delete')
 * ```
 */
export function definePermissionAbility(...permissions: Permission[]): PermissionAbility {
  return defineRequirementsAbility({ permissions })
}

/** An ability requiring **at least one** of the listed permissions. */
export function defineAnyPermissionAbility(...permissions: Permission[]): PermissionAbility {
  return defineRequirementsAbility({ anyPermission: permissions })
}

/**
 * An ability requiring at least one of the listed roles.
 *
 * Prefer permission-based abilities. Roles reach this app through the ID token, so a
 * bearer caller normally carries none and will be denied unless your access tokens
 * include a `roles` claim via a Logto JWT customizer. Logto role names are also
 * mutable display strings that can be renamed in the console, whereas a role is
 * ultimately just a bundle of permissions — so checking permissions tests the same
 * thing more durably.
 */
export function defineRoleAbility(...roles: string[]): PermissionAbility {
  return defineRequirementsAbility({ roles })
}

/** An ability requiring one of `roles` within a specific organization. */
export function defineOrganizationRoleAbility(
  organizationId: string,
  ...roles: string[]
): PermissionAbility {
  return defineRequirementsAbility({ organization: { id: organizationId, roles } })
}

/**
 * How a single entry of {@link definePermissionGates} may be written.
 *
 * A bare permission or an array of them is the common case and means *all* of them;
 * anything else is a full {@link AuthRequirements} object, the same vocabulary used by
 * `requireLogtoUser` and by the client composable.
 */
export type GateSpec = RequirementsInput

function abilityFromSpec(spec: GateSpec): PermissionAbility {
  return defineRequirementsAbility(toRequirements(spec))
}

/**
 * Declares a named set of permission gates in one place.
 *
 * Keys are preserved in the return type, so `gates.viewAssessment` autocompletes, and
 * permission strings are checked against the `Permission` union generated from
 * `logtoRbac.permissions` — a typo is a compile error rather than a silent deny.
 *
 * @example
 * ```ts
 * // shared/utils/abilities.ts
 * export const gates = definePermissionGates({
 *   viewAssessment: 'assessment:view',
 *   manageAssessment: ['assessment:edit', 'assessment:delete'],
 *   reviewAssessment: { anyPermission: ['assessment:edit', 'assessment:share'] },
 *   verifiedEditor: { permissions: ['assessment:edit'], verified: true },
 *   admin: { roles: ['Admin'] },
 * })
 * ```
 */
export function definePermissionGates<const T extends Record<string, GateSpec>>(
  specs: T,
): { [K in keyof T]: PermissionAbility } {
  const gates = {} as { [K in keyof T]: PermissionAbility }

  // Iterated as entries rather than by key lookup, since indexed access on a generic
  // record widens the value to `GateSpec | undefined`.
  for (const [key, spec] of Object.entries(specs) as [keyof T, GateSpec][]) {
    gates[key] = abilityFromSpec(spec)
  }

  return gates
}

/**
 * Resolves every ability against the same context.
 *
 * Each child's own `execute` is used, so each applies its own `allowGuest` rule
 * rather than having the combinator decide for it.
 */
async function evaluate(
  abilities: readonly AnyContextAbility[],
  user: AuthContext | null,
): Promise<AuthorizationResponse[]> {
  return Promise.all(
    abilities.map(async ability =>
      normalizeAuthorizationResponse(await ability.execute(user)),
    ),
  )
}

/**
 * Passes when **at least one** of the given abilities passes (logical OR).
 *
 * On failure the first denial is propagated verbatim, preserving its status code and
 * message rather than replacing them with a generic one.
 *
 * An empty list denies: combinators fail closed.
 */
export function anyOfAbilities(...abilities: AnyContextAbility[]): PermissionAbility {
  return defineContextAbility(async (user) => {
    if (abilities.length === 0) return denyForbidden('No abilities to satisfy.')

    const results = await evaluate(abilities, user)
    if (results.some(result => result.authorized)) return allow()

    return results.find(result => !result.authorized) ?? denyForbidden('Not permitted.')
  })
}

/**
 * Passes only when **every** given ability passes (logical AND).
 *
 * In templates this is usually unnecessary: `<Can :ability="[a, b]">` already
 * requires all of them. It exists for server-side and programmatic composition.
 *
 * An empty list denies rather than being vacuously true, so an accidentally empty
 * list cannot authorize.
 */
export function allOfAbilities(...abilities: AnyContextAbility[]): PermissionAbility {
  return defineContextAbility(async (user) => {
    if (abilities.length === 0) return denyForbidden('No abilities to satisfy.')

    const results = await evaluate(abilities, user)
    return results.find(result => !result.authorized) ?? allow()
  })
}

/**
 * Inverts an ability.
 *
 * Note that inverting a permission gate means guests **pass**, since they fail the
 * original. Useful for "only show this to users who cannot do X" rather than as a
 * security boundary.
 */
export function notAbility(ability: AnyContextAbility): PermissionAbility {
  return defineContextAbility(async (user) => {
    const result = normalizeAuthorizationResponse(await ability.execute(user))
    return result.authorized ? denyForbidden('Not permitted.') : allow()
  })
}
