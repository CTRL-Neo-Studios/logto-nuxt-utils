import { describe, expect, it } from 'vitest'
import {
  describeLogtoOidcError,
  formatLogtoOidcError,
} from '../src/runtime/shared/diagnostics'

/** Mirrors the `LogtoError` shape seen in a real failing callback. */
function logtoError(error: string, errorDescription?: string) {
  return {
    name: 'LogtoError',
    message: 'Error found in the callback URI',
    code: 'callback_uri_verification.error_found',
    data: { name: 'OidcError', error, errorDescription },
  }
}

/**
 * Mirrors `LogtoRequestError` from a failed token exchange.
 *
 * Structurally different from the callback error: it namespaces the code and carries
 * no `error` property at all, which is why it went undetected before.
 */
function logtoRequestError(code: string, message: string) {
  return { name: 'LogtoRequestError', code, message, cause: { status: 400 } }
}

describe('describeLogtoOidcError', () => {
  it('reads the error out of a LogtoError `data` payload', () => {
    const info = describeLogtoOidcError(
      logtoError('invalid_target', 'resource indicator is missing, or unknown'),
    )

    expect(info?.error).toBe('invalid_target')
    expect(info?.description).toBe('resource indicator is missing, or unknown')
  })

  it('follows the cause chain, since Nitro wraps the original error', () => {
    // The payload is never on the top-level object by the time an error hook sees it.
    const wrapped = new Error('[GET] /api/v1/auth/callback') as Error & { cause?: unknown }
    wrapped.cause = logtoError('invalid_target')

    expect(describeLogtoOidcError(wrapped)?.error).toBe('invalid_target')
  })

  it('follows several links of nesting', () => {
    const inner = { cause: logtoError('invalid_scope') }
    const outer = { cause: inner }

    expect(describeLogtoOidcError(outer)?.error).toBe('invalid_scope')
  })

  it('gives up rather than looping on a cyclic cause', () => {
    const cyclic: Record<string, unknown> = { message: 'boom' }
    cyclic.cause = cyclic

    expect(describeLogtoOidcError(cyclic)).toBeUndefined()
  })

  it('ignores errors that are not OIDC errors', () => {
    expect(describeLogtoOidcError(new Error('unrelated'))).toBeUndefined()
    expect(describeLogtoOidcError(undefined)).toBeUndefined()
    expect(describeLogtoOidcError('a string')).toBeUndefined()
    expect(describeLogtoOidcError({ error: 42 })).toBeUndefined()
  })

  it('accepts a bare OidcError without a wrapper', () => {
    expect(describeLogtoOidcError({ error: 'access_denied' })?.error).toBe('access_denied')
  })

  it('reads snake_case descriptions too', () => {
    const info = describeLogtoOidcError({ error: 'invalid_scope', error_description: 'nope' })
    expect(info?.description).toBe('nope')
  })

  describe('hints', () => {
    it('points invalid_target at the resources config', () => {
      const info = describeLogtoOidcError(logtoError('invalid_target'))

      expect(info?.hint).toContain('logtoRbac.resources')
      expect(info?.hint).toContain('Logto console')
    })

    it('points invalid_scope at the permissions config', () => {
      expect(describeLogtoOidcError(logtoError('invalid_scope'))?.hint)
        .toContain('logtoRbac.permissions')
    })

    it('omits a hint for codes it does not recognise', () => {
      const info = describeLogtoOidcError(logtoError('some_future_code'))

      expect(info?.error).toBe('some_future_code')
      expect(info?.hint).toBeUndefined()
    })

    /**
     * The bug this guards: `invalid_target` from a token exchange means the resource
     * IS registered but the session's refresh token predates it. Sending someone to
     * re-audit correct console config wastes their time, so the two must differ.
     */
    it('tells a stale session to sign in again rather than blaming the console', () => {
      const info = describeLogtoOidcError(
        logtoRequestError('oidc.invalid_target', 'Invalid resource indicator.'),
      )

      expect(info?.error).toBe('invalid_target')
      expect(info?.source).toBe('token')
      expect(info?.hint).toMatch(/sign in again/iu)
    })

    it('still blames config for invalid_target from the authorization endpoint', () => {
      const info = describeLogtoOidcError(logtoError('invalid_target'))

      expect(info?.source).toBe('authorization')
      expect(info?.hint).not.toMatch(/sign in again/iu)
    })

    it('falls back to the generic hint when a code has no source-specific one', () => {
      // `invalid_scope` means the same thing from either endpoint, so the token-side
      // failure must not silently lose its hint.
      expect(describeLogtoOidcError(logtoRequestError('oidc.invalid_scope', 'nope'))?.hint)
        .toContain('logtoRbac.permissions')
    })

    it('ignores non-oidc Logto request error codes', () => {
      // Logto's own API errors share the class but are not OAuth failures.
      expect(describeLogtoOidcError(logtoRequestError('user.not_found', 'nope')))
        .toBeUndefined()
    })
  })
})

describe('formatLogtoOidcError', () => {
  it('includes the code, description and hint', () => {
    const message = formatLogtoOidcError({
      error: 'invalid_target',
      description: 'resource indicator is missing, or unknown',
      hint: 'Check your resources.',
    })

    expect(message).toContain('invalid_target')
    expect(message).toContain('resource indicator is missing')
    expect(message).toContain('Check your resources.')
  })

  it('works with only a code', () => {
    expect(formatLogtoOidcError({ error: 'oops' })).toBe('Logto returned "oops"')
  })
})
