import { describe, expect, it } from 'vitest'
import type { AuthContext } from '../src/runtime/types'
import {
  checkRequirements,
  ctxIsVerified,
  ctxSatisfies,
  toRequirements,
} from '../src/runtime/shared/requirements'

function context(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    isAuthenticated: true,
    source: 'session',
    userId: 'user_1',
    roles: [],
    scopes: [],
    organizations: [],
    organizationRoles: {},
    ...overrides,
  }
}

describe('checkRequirements', () => {
  describe('authentication', () => {
    it('fails with 401 for a null context and runs no further checks', () => {
      // Call sites must never need their own null guard.
      const result = checkRequirements(null, { permissions: ['a'] })

      expect(result).toMatchObject({
        ok: false,
        failed: 'unauthenticated',
        statusCode: 401,
      })
    })

    it('fails with 401 for an anonymous context', () => {
      const result = checkRequirements(
        context({ isAuthenticated: false, source: 'anonymous' }),
        {},
      )

      expect(result).toMatchObject({ ok: false, statusCode: 401 })
    })

    it('passes an authenticated caller when nothing else is required', () => {
      expect(checkRequirements(context()).ok).toBe(true)
      expect(checkRequirements(context(), {}).ok).toBe(true)
    })
  })

  describe('permissions', () => {
    it('requires every listed permission', () => {
      const reqs = { permissions: ['a', 'b'] } as const

      expect(checkRequirements(context({ scopes: ['a', 'b'] }), reqs).ok).toBe(true)
      expect(checkRequirements(context({ scopes: ['a'] }), reqs).ok).toBe(false)
    })

    it('reports only the missing permissions, with 403', () => {
      const result = checkRequirements(context({ scopes: ['a'] }), {
        permissions: ['a', 'b'],
      })

      expect(result).toMatchObject({ ok: false, failed: 'permissions', statusCode: 403 })
      if (!result.ok) {
        expect(result.message).toContain('b')
        expect(result.held).toEqual(['a'])
      }
    })

    it('treats an empty permissions array as no constraint', () => {
      expect(checkRequirements(context(), { permissions: [] }).ok).toBe(true)
    })
  })

  describe('anyPermission', () => {
    it('passes when at least one is held', () => {
      const reqs = { anyPermission: ['a', 'b'] } as const

      expect(checkRequirements(context({ scopes: ['b'] }), reqs).ok).toBe(true)
      expect(checkRequirements(context({ scopes: ['c'] }), reqs).ok).toBe(false)
    })

    it('reports the anyPermission failure distinctly', () => {
      const result = checkRequirements(context(), { anyPermission: ['a'] })
      expect(result).toMatchObject({ failed: 'anyPermission', statusCode: 403 })
    })
  })

  describe('roles', () => {
    it('matches any listed role exactly', () => {
      const reqs = { roles: ['Admin', 'Moderator'] } as const

      expect(checkRequirements(context({ roles: ['Moderator'] }), reqs).ok).toBe(true)
      expect(checkRequirements(context({ roles: ['Student'] }), reqs).ok).toBe(false)
    })

    it('accepts role names outside any declared set', () => {
      // Logto role names are arbitrary runtime strings, e.g. 'Test Localhost'.
      const result = checkRequirements(context({ roles: ['Test Localhost'] }), {
        roles: ['Test Localhost'],
      })

      expect(result.ok).toBe(true)
    })
  })

  describe('organization', () => {
    it('requires membership when no roles are given', () => {
      const reqs = { organization: { id: 'org_1' } }

      expect(checkRequirements(context({ organizations: ['org_1'] }), reqs).ok).toBe(true)
      expect(checkRequirements(context({ organizations: ['org_2'] }), reqs).ok).toBe(false)
    })

    it('requires one of the listed roles within that organization', () => {
      const reqs = { organization: { id: 'org_1', roles: ['owner'] } }

      expect(checkRequirements(
        context({ organizations: ['org_1'], organizationRoles: { org_1: ['owner'] } }),
        reqs,
      ).ok).toBe(true)

      expect(checkRequirements(
        context({ organizations: ['org_1'], organizationRoles: { org_1: ['member'] } }),
        reqs,
      ).ok).toBe(false)
    })

    it('does not let a role in another organization satisfy the check', () => {
      const result = checkRequirements(
        context({ organizations: ['org_1'], organizationRoles: { org_2: ['owner'] } }),
        { organization: { id: 'org_1', roles: ['owner'] } },
      )

      expect(result).toMatchObject({ failed: 'organization' })
    })
  })

  describe('verified', () => {
    it('is not required by default', () => {
      const ctx = context({ claims: { email_verified: false } })
      expect(checkRequirements(ctx, { permissions: [] }).ok).toBe(true)
    })

    it('rejects an explicitly unverified caller when required', () => {
      const result = checkRequirements(
        context({ claims: { email_verified: false } }),
        { verified: true },
      )

      expect(result).toMatchObject({ failed: 'verified', statusCode: 403 })
    })

    it('passes when the claim is absent, rather than locking the caller out', () => {
      // `email_verified` is an ID-token claim, so a bearer caller has none. Treating
      // absence as unverified would reject every service-to-service call.
      expect(checkRequirements(context(), { verified: true }).ok).toBe(true)
      expect(checkRequirements(context({ source: 'bearer' }), { verified: true }).ok).toBe(true)
    })
  })

  describe('check ordering', () => {
    it('reports the permission failure before the role failure', () => {
      // Permissions are the primary mechanism, so their failure is the more
      // actionable message when several constraints fail at once.
      const result = checkRequirements(context(), {
        permissions: ['a'],
        roles: ['Admin'],
        verified: true,
      })

      expect(result).toMatchObject({ failed: 'permissions' })
    })

    it('requires all constraints together to pass', () => {
      const ctx = context({
        scopes: ['a', 'b'],
        roles: ['Admin'],
        organizations: ['org_1'],
        organizationRoles: { org_1: ['owner'] },
        claims: { email_verified: true },
      })

      const result = checkRequirements(ctx, {
        permissions: ['a'],
        anyPermission: ['b', 'z'],
        roles: ['Admin'],
        organization: { id: 'org_1', roles: ['owner'] },
        verified: true,
      })

      expect(result.ok).toBe(true)
    })
  })
})

describe('ctxSatisfies', () => {
  it('is the boolean form and is null-safe', () => {
    expect(ctxSatisfies(null)).toBe(false)
    expect(ctxSatisfies(undefined, { permissions: ['a'] })).toBe(false)
    expect(ctxSatisfies(context({ scopes: ['a'] }), { permissions: ['a'] })).toBe(true)
  })
})

describe('ctxIsVerified', () => {
  it('reads email_verified, defaulting to verified when absent', () => {
    expect(ctxIsVerified(context({ claims: { email_verified: true } }))).toBe(true)
    expect(ctxIsVerified(context({ claims: { email_verified: false } }))).toBe(false)
    expect(ctxIsVerified(context())).toBe(true)
    expect(ctxIsVerified(context({ claims: { email_verified: 'yes' } }))).toBe(true)
  })
})

describe('toRequirements', () => {
  it('expands a bare permission and an array into `permissions`', () => {
    expect(toRequirements('a')).toEqual({ permissions: ['a'] })
    expect(toRequirements(['a', 'b'])).toEqual({ permissions: ['a', 'b'] })
  })

  it('passes a requirements object through untouched', () => {
    const reqs = { anyPermission: ['a'], verified: true } as const
    expect(toRequirements(reqs)).toBe(reqs)
  })
})
