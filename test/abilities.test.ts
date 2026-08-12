import { describe, expect, it } from 'vitest'
import { normalizeAuthorizationResponse } from 'nuxt-authorization/utils'
import type { AuthContext } from '../src/runtime/types'
import { profileFromClaims } from '../src/runtime/shared/core'
import {
  allOfAbilities,
  anyOfAbilities,
  defineAnyPermissionAbility,
  defineOrganizationRoleAbility,
  definePermissionAbility,
  definePermissionGates,
  defineRoleAbility,
  notAbility,
  type PermissionAbility,
} from '../src/runtime/shared/abilities'

/**
 * Abilities are exercised directly against synthetic contexts.
 *
 * Minting a real Logto session in a test is not feasible, and these are pure
 * functions of the auth context, so calling `execute` is both the honest and the
 * thorough way to cover AND / OR / NOT, roles and the 401-vs-403 distinction.
 */
function context(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    isAuthenticated: true,
    source: 'session',
    userId: 'user_1',
    roles: [],
    scopes: [],
    organizations: [],
    organizationRoles: {},
    profile: profileFromClaims(undefined),
    ...overrides,
  }
}

async function run(ability: PermissionAbility, user: AuthContext | null) {
  return normalizeAuthorizationResponse(await ability.execute(user))
}

describe('permission abilities', () => {
  describe('status codes', () => {
    it('reports 401 for a guest rather than 403', async () => {
      // The distinction matters: a client needs to know whether to redirect to
      // sign-in or to show "you may not do this".
      const result = await run(definePermissionAbility('a'), null)

      expect(result.authorized).toBe(false)
      expect(result.statusCode).toBe(401)
    })

    it('reports 401 for an anonymous context object', async () => {
      const result = await run(
        definePermissionAbility('a'),
        context({ isAuthenticated: false, source: 'anonymous', userId: undefined }),
      )

      expect(result.statusCode).toBe(401)
    })

    it('reports 403 when signed in but lacking the permission', async () => {
      const result = await run(definePermissionAbility('a'), context({ scopes: ['b'] }))

      expect(result.authorized).toBe(false)
      expect(result.statusCode).toBe(403)
      expect(result.message).toContain('a')
    })
  })

  describe('definePermissionAbility', () => {
    it('requires every permission', async () => {
      const ability = definePermissionAbility('a', 'b')

      expect((await run(ability, context({ scopes: ['a', 'b'] }))).authorized).toBe(true)
      expect((await run(ability, context({ scopes: ['a'] }))).authorized).toBe(false)
    })

    it('names only the missing permissions', async () => {
      const result = await run(definePermissionAbility('a', 'b'), context({ scopes: ['a'] }))

      expect(result.message).toContain('b')
      expect(result.message).not.toContain('a,')
    })
  })

  describe('defineAnyPermissionAbility', () => {
    it('passes when one permission is held', async () => {
      const ability = defineAnyPermissionAbility('a', 'b')

      expect((await run(ability, context({ scopes: ['b'] }))).authorized).toBe(true)
      expect((await run(ability, context({ scopes: ['c'] }))).authorized).toBe(false)
    })
  })

  describe('defineRoleAbility', () => {
    it('matches any listed role', async () => {
      const ability = defineRoleAbility('Admin', 'Moderator')

      expect((await run(ability, context({ roles: ['Moderator'] }))).authorized).toBe(true)
      expect((await run(ability, context({ roles: ['Student'] }))).authorized).toBe(false)
    })

    it('denies a bearer caller that carries no roles', async () => {
      // Roles reach the app through the ID token, so an access token normally asserts
      // permissions but not role names. This is the default Logto behaviour.
      const result = await run(
        defineRoleAbility('Admin'),
        context({ source: 'bearer', roles: [], scopes: ['a'] }),
      )

      expect(result.authorized).toBe(false)
    })

    it('honours roles on a bearer caller when the token does carry them', async () => {
      // A Logto JWT customizer can add a `roles` claim to access tokens. Since the
      // token is fully verified before its claims are read, discarding roles that are
      // present would be wrong.
      const result = await run(
        defineRoleAbility('Admin'),
        context({ source: 'bearer', roles: ['Admin'] }),
      )

      expect(result.authorized).toBe(true)
    })
  })

  describe('defineOrganizationRoleAbility', () => {
    it('scopes the role check to one organization', async () => {
      const ability = defineOrganizationRoleAbility('org_1', 'owner')

      expect(
        (await run(ability, context({
          organizations: ['org_1'],
          organizationRoles: { org_1: ['owner'] },
        }))).authorized,
      ).toBe(true)
      expect(
        (await run(ability, context({
          organizations: ['org_2'],
          organizationRoles: { org_2: ['owner'] },
        }))).authorized,
      ).toBe(false)
    })
  })

  describe('definePermissionGates', () => {
    const gates = definePermissionGates({
      single: 'a',
      allShorthand: ['a', 'b'],
      allExplicit: { permissions: ['a', 'b'] },
      anyExplicit: { anyPermission: ['a', 'b'] },
      byRole: { roles: ['Admin'] },
      byOrgRole: { organization: { id: 'org_1', roles: ['owner'] } },
      verifiedOnly: { permissions: ['a'], verified: true },
    })

    it('treats a bare string as a single permission', async () => {
      expect((await run(gates.single, context({ scopes: ['a'] }))).authorized).toBe(true)
    })

    it('treats a bare array as requiring all of them', async () => {
      expect((await run(gates.allShorthand, context({ scopes: ['a'] }))).authorized).toBe(false)
      expect((await run(gates.allShorthand, context({ scopes: ['a', 'b'] }))).authorized).toBe(true)
    })

    it('supports the explicit permissions / anyPermission forms', async () => {
      expect((await run(gates.allExplicit, context({ scopes: ['a'] }))).authorized).toBe(false)
      expect((await run(gates.anyExplicit, context({ scopes: ['a'] }))).authorized).toBe(true)
    })

    it('supports role and organization forms', async () => {
      expect((await run(gates.byRole, context({ roles: ['Admin'] }))).authorized).toBe(true)
      expect((await run(gates.byOrgRole, context({
        organizations: ['org_1'],
        organizationRoles: { org_1: ['owner'] },
      }))).authorized).toBe(true)
    })

    it('does not let a plain role satisfy an organization gate', async () => {
      const result = await run(gates.byOrgRole, context({ roles: ['owner'] }))
      expect(result.authorized).toBe(false)
    })

    it('combines permission and verification requirements', async () => {
      expect((await run(gates.verifiedOnly, context({
        scopes: ['a'],
        claims: { email_verified: true },
      }))).authorized).toBe(true)

      expect((await run(gates.verifiedOnly, context({
        scopes: ['a'],
        claims: { email_verified: false },
      }))).authorized).toBe(false)
    })
  })

  describe('combinators', () => {
    const canA = definePermissionAbility('a')
    const canB = definePermissionAbility('b')

    it('anyOfAbilities is an OR', async () => {
      const ability = anyOfAbilities(canA, canB)

      expect((await run(ability, context({ scopes: ['b'] }))).authorized).toBe(true)
      expect((await run(ability, context({ scopes: ['c'] }))).authorized).toBe(false)
    })

    it('anyOfAbilities propagates the first denial verbatim', async () => {
      // Preserving the child's status code is what keeps a guest a 401 rather than
      // being flattened into a generic 403 by the combinator.
      const result = await run(anyOfAbilities(canA, canB), null)

      expect(result.statusCode).toBe(401)
    })

    it('allOfAbilities is an AND', async () => {
      const ability = allOfAbilities(canA, canB)

      expect((await run(ability, context({ scopes: ['a', 'b'] }))).authorized).toBe(true)
      expect((await run(ability, context({ scopes: ['a'] }))).authorized).toBe(false)
    })

    it('fails closed when given no abilities', async () => {
      // An accidentally empty list must never authorize, even though an empty AND is
      // vacuously true.
      expect((await run(allOfAbilities(), context({ scopes: ['a'] }))).authorized).toBe(false)
      expect((await run(anyOfAbilities(), context({ scopes: ['a'] }))).authorized).toBe(false)
    })

    it('notAbility inverts', async () => {
      const ability = notAbility(canA)

      expect((await run(ability, context({ scopes: ['a'] }))).authorized).toBe(false)
      expect((await run(ability, context({ scopes: ['b'] }))).authorized).toBe(true)
    })

    it('composes with a domain ability that takes arguments', async () => {
      // The realistic pattern: an ownership check OR an override permission.
      const isOwner = {
        allowGuest: false,
        original: (user: AuthContext) => user.userId === 'user_1',
        execute: (user: AuthContext | null) => user?.userId === 'user_1',
      }

      const ability = anyOfAbilities(isOwner, canA)

      expect((await run(ability, context({ userId: 'user_1' }))).authorized).toBe(true)
      expect((await run(ability, context({ userId: 'other', scopes: ['a'] }))).authorized).toBe(true)
      expect((await run(ability, context({ userId: 'other' }))).authorized).toBe(false)
    })
  })
})
