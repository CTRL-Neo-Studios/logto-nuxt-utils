/**
 * Turns Logto's OIDC errors into something actionable.
 *
 * Logto surfaces configuration mistakes as bare OAuth error codes far from the config
 * that caused them. `invalid_target` in particular says only "resource indicator is
 * missing, or unknown", with nothing to connect it to `logtoRbac.resources`.
 *
 * Worse, the *same* code means two different things depending on which endpoint
 * rejected it, and only one of them is a configuration problem — see
 * {@link LogtoOidcErrorSource}.
 *
 * Pure and dependency-free so it can be unit tested directly.
 */

/**
 * Which Logto endpoint rejected the request.
 *
 * This distinction is the whole point of the module: `invalid_target` from the
 * authorization endpoint means the resource is not registered in Logto, whereas the
 * same code from the token endpoint means the resource is registered but *this
 * session's refresh token* was issued before it was requested. The first needs a
 * config or console change; the second needs nothing but a fresh sign-in.
 *
 * Derived from the error's *shape* rather than its URL: a failed authorization
 * request comes back through the callback as a `LogtoError` wrapping an `OidcError`,
 * while a failed token exchange throws `LogtoRequestError` with a prefixed `code` and
 * the raw `Response` as its cause.
 */
export type LogtoOidcErrorSource = 'authorization' | 'token'

export interface LogtoOidcErrorInfo {
  /** The OAuth error code, e.g. `invalid_target`. */
  error: string
  /** Logto's description, when present. */
  description?: string
  /** Which endpoint rejected the request, when it can be determined. */
  source?: LogtoOidcErrorSource
  /** What to actually do about it, when we recognise the code. */
  hint?: string
}

/**
 * Hints keyed by error code, and by source where the same code means two different
 * things.
 *
 * Only the codes a misconfiguration of this module realistically produces.
 */
const HINTS: Record<string, string> = {
  invalid_target:
    'Logto rejected the requested API resource. Every entry in `logtoRbac.resources` '
    + 'and `logtoRbac.additionalResources` must exist as an API resource in the Logto '
    + 'console, with the indicator matching byte-for-byte (watch for a trailing slash). '
    + 'Placeholder values such as https://example.com/api/v1 will always fail.',
  // Same code, entirely different cause. Resources and scopes are bound to the
  // refresh token when it is issued, so a session that predates a newly added
  // resource can never exchange for a token against it — Logto reports the resource
  // as "unknown" for that token even though it is registered and the authorization
  // endpoint accepts it. Sending someone to re-check the console here wastes their
  // time on config that is already correct.
  'invalid_target@token':
    'Logto rejected the resource for this session\'s refresh token. If the resource IS '
    + 'registered in the Logto console, the session simply predates it: resources and '
    + 'scopes are granted at sign-in and cannot be added to an existing refresh token. '
    + 'Sign out and sign in again. If it persists after a fresh sign-in, the indicator '
    + 'really is missing from the console or does not match byte-for-byte.',
  invalid_scope:
    'Logto rejected a requested scope. Every entry in `logtoRbac.permissions` must '
    + 'exist as a permission on the API resource it belongs to, and any scopes declared '
    + 'for `additionalResources` must exist on those resources.',
  access_denied:
    'The user declined consent, or is not permitted to sign in to this application.',
  invalid_client:
    'Logto rejected the application credentials. Check `logto.appId` and '
    + '`logto.appSecret`, and that the app type in Logto is "Traditional web".',
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

/**
 * Reads an OIDC error out of a value, if it looks like one.
 *
 * Recognises three shapes:
 *
 * - a bare `OidcError` — `{ error, errorDescription }`
 * - a `LogtoError` carrying one under `data`
 * - a `LogtoRequestError` from a token exchange — `{ code: 'oidc.invalid_target',
 *   message }`, which has no `error` property at all and was therefore invisible to
 *   this module until the `code` form was handled here
 */
function readOidcError(value: unknown): Omit<LogtoOidcErrorInfo, 'hint'> | undefined {
  if (!isRecord(value)) return undefined

  const candidate = isRecord(value.data) ? value.data : value
  const error = candidate.error

  if (typeof error === 'string') {
    const description = candidate.errorDescription ?? candidate.error_description
    return {
      error,
      description: typeof description === 'string' ? description : undefined,
      source: 'authorization',
    }
  }

  // `LogtoRequestError` namespaces its code, e.g. `oidc.invalid_target`. Only the
  // `oidc.` family maps onto an OAuth error code; other prefixes are Logto's own
  // API errors and are none of this module's business.
  const code = candidate.code
  if (typeof code !== 'string' || !code.startsWith('oidc.')) return undefined

  return {
    error: code.slice('oidc.'.length),
    description: typeof candidate.message === 'string' ? candidate.message : undefined,
    // The requester only ever runs for back-channel calls — token, userinfo, JWKS —
    // never for the browser's authorization redirect.
    source: 'token',
  }
}

/**
 * Finds a Logto OIDC error anywhere in an error's `cause` chain.
 *
 * The chain matters because Nitro wraps the original `LogtoError` before it reaches
 * any error hook, so the useful payload is never on the top-level object.
 *
 * @param depth Maximum links to follow, guarding against a cyclic `cause`.
 */
export function describeLogtoOidcError(
  error: unknown,
  depth = 5,
): LogtoOidcErrorInfo | undefined {
  let current: unknown = error

  for (let i = 0; i <= depth && isRecord(current); i++) {
    const found = readOidcError(current)

    if (found) {
      return {
        ...found,
        // A source-specific hint wins over the generic one for the same code, which
        // is what lets `invalid_target` from a token exchange say "sign in again"
        // instead of sending someone to audit correct config.
        hint: HINTS[`${found.error}@${found.source}`] ?? HINTS[found.error],
      }
    }

    current = current.cause
  }

  return undefined
}

/** Formats a recognised OIDC error as a single log-friendly message. */
export function formatLogtoOidcError(info: LogtoOidcErrorInfo): string {
  const parts = [`Logto returned "${info.error}"`]

  if (info.description) parts.push(`: ${info.description}`)
  if (info.hint) parts.push(`\n\n${info.hint}`)

  return parts.join('')
}
