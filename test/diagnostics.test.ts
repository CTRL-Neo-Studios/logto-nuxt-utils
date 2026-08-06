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
