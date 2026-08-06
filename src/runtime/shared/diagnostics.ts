/**
 * Turns Logto's OIDC errors into something actionable.
 *
 * Logto surfaces configuration mistakes as bare OAuth error codes at the callback,
 * far from the config that caused them. `invalid_target` in particular says only
 * "resource indicator is missing, or unknown", with nothing to connect it to
 * `logtoRbac.resources`.
 *
 * Pure and dependency-free so it can be unit tested directly.
 */

export interface LogtoOidcErrorInfo {
  /** The OAuth error code, e.g. `invalid_target`. */
  error: string
  /** Logto's description, when present. */
  description?: string
  /** What to actually do about it, when we recognise the code. */
  hint?: string
}

/** Hints for the codes a misconfiguration of this module realistically produces. */
const HINTS: Record<string, string> = {
  invalid_target:
    'Logto rejected the requested API resource. Every entry in `logtoRbac.resources` '
    + 'and `logtoRbac.additionalResources` must exist as an API resource in the Logto '
    + 'console, with the indicator matching byte-for-byte (watch for a trailing slash). '
    + 'Placeholder values such as https://example.com/api/v1 will always fail.',
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
 * Extracts `{ error, errorDescription }` from a value, if it looks like one.
 *
 * Handles both a bare `OidcError` and a `LogtoError` carrying one under `data`.
 */
function readOidcError(value: unknown): { error: string, description?: string } | undefined {
  if (!isRecord(value)) return undefined

  const candidate = isRecord(value.data) ? value.data : value
  const error = candidate.error

  if (typeof error !== 'string') return undefined

  const description = candidate.errorDescription ?? candidate.error_description
  return {
    error,
    description: typeof description === 'string' ? description : undefined,
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
        error: found.error,
        description: found.description,
        hint: HINTS[found.error],
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
