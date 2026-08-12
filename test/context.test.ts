import { describe, expect, it } from 'vitest'
import {
  contextFromAccessTokenClaims,
  createAnonymousContext,
  parseOrganizationRoles,
  parseScopeClaim,
  profileFromClaims,
  toStringArray,
} from '../src/runtime/shared/core'

/**
 * Claim normalisation is where every authorization decision ultimately comes from, so
 * it is worth covering directly rather than only through the abilities.
 */
describe('claim parsing', () => {
  describe('toStringArray', () => {
    it('returns an empty array for absent claims', () => {
      // Logto omits a claim entirely when its scope was not granted, so `roles` is
      // `undefined` rather than `[]` — the difference between a crash and a denial.
      expect(toStringArray(undefined)).toEqual([])
      expect(toStringArray(null)).toEqual([])
    })

    it('drops non-string entries', () => {
      expect(toStringArray(['a', 1, null, 'b', {}])).toEqual(['a', 'b'])
    })
  })

  describe('parseScopeClaim', () => {
    it('splits the space-delimited scope string', () => {
      expect(parseScopeClaim('a b c')).toEqual(['a', 'b', 'c'])
    })

    it('tolerates irregular whitespace and non-strings', () => {
      expect(parseScopeClaim('  a \n b  ')).toEqual(['a', 'b'])
      expect(parseScopeClaim(undefined)).toEqual([])
      expect(parseScopeClaim(['a'])).toEqual([])
    })
  })

  describe('parseOrganizationRoles', () => {
    it('groups `orgId:role` entries by organization', () => {
      expect(parseOrganizationRoles(['org1:admin', 'org1:member', 'org2:owner'])).toEqual({
        org1: ['admin', 'member'],
        org2: ['owner'],
      })
    })

    it('splits on the first colon only, since role names may contain colons', () => {
      expect(parseOrganizationRoles(['org1:some:role'])).toEqual({ org1: ['some:role'] })
    })

    it('ignores malformed entries', () => {
      expect(parseOrganizationRoles(['noseparator', ':leading', 'trailing:'])).toEqual({})
    })
  })

  describe('profileFromClaims', () => {
    it('normalises present claims, treating blank and wrong-typed ones as absent', () => {
      expect(profileFromClaims({
        sub: 'user_1',
        name: 'Ada',
        email: '',
        email_verified: true,
        picture: 42,
      })).toEqual({
        sub: 'user_1',
        name: 'Ada',
        username: null,
        email: null,
        emailVerified: true,
        phoneNumber: null,
        phoneNumberVerified: false,
        picture: null,
      })
    })

    it('fills every key for absent claims, so `profile.name` needs no optional chaining', () => {
      const profile = profileFromClaims(undefined)

      expect(profile).toEqual({
        sub: null,
        name: null,
        username: null,
        email: null,
        emailVerified: false,
        phoneNumber: null,
        phoneNumberVerified: false,
        picture: null,
      })
      expect(Object.values(profile).some(value => value === undefined)).toBe(false)
    })
  })
})

describe('contextFromAccessTokenClaims', () => {
  it('reads permissions from the scope claim', () => {
    const ctx = contextFromAccessTokenClaims({ sub: 'user_1', scope: 'a b' })

    expect(ctx).toMatchObject({
      isAuthenticated: true,
      source: 'bearer',
      userId: 'user_1',
      scopes: ['a', 'b'],
    })
  })

  it('yields no roles for a default Logto access token', () => {
    // `roles` is an ID-token claim, so a plain access token has none.
    const ctx = contextFromAccessTokenClaims({ sub: 'user_1', scope: 'a' })
    expect(ctx.roles).toEqual([])
  })

  it('carries a sparse profile and counts as verified without the claim', () => {
    // An access token has `sub` but no profile claims, and no `email_verified` at all —
    // treating that absence as unverified would reject every service-to-service call.
    const ctx = contextFromAccessTokenClaims({ sub: 'user_1', scope: 'a', email: 'a@b.c' })

    expect(ctx.profile).toMatchObject({ sub: 'user_1', email: 'a@b.c', name: null })
    expect(ctx.isVerified).toBe(true)
  })

  it('reports an explicitly unverified bearer caller', () => {
    const ctx = contextFromAccessTokenClaims({ sub: 'user_1', email_verified: false })
    expect(ctx.isVerified).toBe(false)
  })

  it('honours a roles claim added by a JWT customizer', () => {
    // Logto can be configured to include roles in access tokens. The token is fully
    // verified before this runs, so a present claim must not be discarded.
    const ctx = contextFromAccessTokenClaims({
      sub: 'user_1',
      scope: 'a',
      roles: ['Admin', 'Student'],
    })

    expect(ctx.roles).toEqual(['Admin', 'Student'])
  })

  it('tolerates a malformed roles claim', () => {
    const ctx = contextFromAccessTokenClaims({ sub: 'user_1', roles: 'Admin' })
    expect(ctx.roles).toEqual([])
  })

  it('omits userId when `sub` is missing or not a string', () => {
    expect(contextFromAccessTokenClaims({}).userId).toBeUndefined()
    expect(contextFromAccessTokenClaims({ sub: 42 }).userId).toBeUndefined()
  })
})

describe('createAnonymousContext', () => {
  it('returns a fresh object each time', () => {
    // A frozen singleton would let one caller mutate another's arrays.
    const a = createAnonymousContext()
    const b = createAnonymousContext()

    a.roles.push('mutated')

    expect(b.roles).toEqual([])
    expect(b.isAuthenticated).toBe(false)
    expect(b.source).toBe('anonymous')
  })
})
