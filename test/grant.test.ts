import { describe, expect, it } from 'vitest'
import { fingerprintPermissions } from '../src/runtime/server/utils/grant'

/**
 * The fingerprint decides whether a live session is told to re-authorize, so both of its
 * failure modes are user-visible: too sensitive and every deploy nags every user, too
 * insensitive and a newly added permission is silently never granted.
 */
describe('fingerprintPermissions', () => {
  it('ignores the order of the permission list', () => {
    // `permissions` is hand-maintained in nuxt.config; reordering or regrouping it must
    // not invalidate every session in production.
    expect(fingerprintPermissions(['a:b', 'c:d']))
      .toBe(fingerprintPermissions(['c:d', 'a:b']))
  })

  it('changes when a permission is added', () => {
    // This is the detection itself: an added permission cannot reach an existing grant,
    // so it has to be noticed.
    expect(fingerprintPermissions(['a:b']))
      .not.toBe(fingerprintPermissions(['a:b', 'c:d']))
  })

  it('changes when a permission is removed', () => {
    expect(fingerprintPermissions(['a:b', 'c:d']))
      .not.toBe(fingerprintPermissions(['c:d']))
  })

  it('distinguishes lists that differ only in where the entries are split', () => {
    // Without a separator between entries the digest would see one concatenated string
    // and treat these as the same list.
    expect(fingerprintPermissions(['ab', 'c']))
      .not.toBe(fingerprintPermissions(['a', 'bc']))
  })

  it('returns a stable non-empty digest for an empty list', () => {
    // Configuring no permissions is legal, and must still produce a value that can be
    // stored and compared rather than an empty string.
    expect(fingerprintPermissions([])).toBe(fingerprintPermissions([]))
    expect(fingerprintPermissions([])).not.toBe('')
  })
})
