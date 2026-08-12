import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose'

/**
 * A minimal Logto tenant, in-process.
 *
 * Every other request in this fixture short-circuits at `isAuthenticated()` returning
 * `false`, so nothing that happens only to a *signed-in* session — which is all of the
 * token revalidation — could otherwise be exercised. Standing up discovery, JWKS and the
 * token endpoint costs one key pair and lets the real `@logto/client` run its real
 * refresh grant, with no network and no credentials.
 *
 * Deliberately not a stub of this module's own code: the point is to prove that this
 * module drives `@logto/client` correctly, so `@logto/client` has to be what runs.
 */
const ALGORITHM = 'RS256'

/** Matches `logto.endpoint` in the fixture's nuxt.config; the fetch shim keys off it. */
export const ENDPOINT = 'https://fixture.logto.test'
export const ISSUER = `${ENDPOINT}/oidc`
export const APP_ID = 'fixture-app-id'
export const USER_ID = 'fixture-user-id'

/** Access-token lifetime, matching Logto's own default. */
const TOKEN_TTL = 3600

/** The tenant's signing material: the private key to mint with, the public half to verify. */
export interface TenantKeys {
  privateKey: CryptoKey
  publicKey: CryptoKey
  jwk: JWK
}

/** Generated once per server process, since the tests only need one tenant. */
let keys: Promise<TenantKeys> | undefined

export function useTenantKeys(): Promise<TenantKeys> {
  keys ??= generateKeyPair(ALGORITHM).then(async ({ privateKey, publicKey }) => ({
    privateKey,
    publicKey,
    jwk: { ...await exportJWK(publicKey), alg: ALGORITHM, use: 'sig', kid: 'fixture-key' },
  }))

  return keys
}

/**
 * What the tenant currently grants, mutable at runtime.
 *
 * This stands in for the Logto console: a test changes these the way an administrator
 * would, then asserts a live session picks the change up. `refreshGrants` is what proves
 * the cached token was genuinely discarded rather than the values merely differing.
 */
export const tenant = {
  roles: ['editor'],
  scopes: ['assessment:view', 'assessment:edit'],
  refreshGrants: 0,
}

/**
 * Mints an ID token the way Logto does.
 *
 * `@logto/client` verifies the signature, `aud`, `iss` and — within a 300s tolerance —
 * `iat`, so a hand-rolled payload is rejected. `issuedAt` is explicit because this
 * module's bookkeeping keys off `iat`: a refresh grant has to produce a newer one, and a
 * re-authorization has to be distinguishable from one.
 */
export async function mintIdToken(issuedAt: number, roles: readonly string[]): Promise<string> {
  const { privateKey } = await useTenantKeys()

  return new SignJWT({
    name: 'Fixture User',
    email: 'fixture@example.com',
    email_verified: true,
    roles: [...roles],
  })
    .setProtectedHeader({ alg: ALGORITHM, kid: 'fixture-key' })
    .setIssuer(ISSUER)
    .setAudience(APP_ID)
    .setSubject(USER_ID)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + TOKEN_TTL)
    .sign(privateKey)
}

/**
 * Mints an access token for `resource`, carrying only the scopes that resource defines.
 *
 * Logto applies the granted scopes to every requested resource, and each token carries
 * only its own resource's, which is why this module unions scopes across resources. The
 * split reproduces that instead of handing every resource everything.
 */
export async function mintAccessToken(
  resource: string,
  scopes: readonly string[],
): Promise<string> {
  const { privateKey } = await useTenantKeys()
  const issuedAt = Math.floor(Date.now() / 1000)
  const isReports = resource.endsWith('/reports/v1')
  const owned = scopes.filter(scope => scope.startsWith('report:') === isReports)

  return new SignJWT({ scope: owned.join(' '), client_id: APP_ID })
    .setProtectedHeader({ alg: ALGORITHM, kid: 'fixture-key' })
    .setIssuer(ISSUER)
    .setAudience(resource)
    .setSubject(USER_ID)
    .setIssuedAt(issuedAt)
    // A full hour, so a cached token stays valid for the whole test run: anything that
    // changes did so because the cache was discarded, not because the token expired.
    .setExpirationTime(issuedAt + TOKEN_TTL)
    .sign(privateKey)
}

/**
 * Serves the tenant's OIDC endpoints.
 *
 * Returns `undefined` for anything else so the caller can fall through to real `fetch`.
 */
export async function handleTenantRequest(request: Request): Promise<Response | undefined> {
  const url = new URL(request.url)

  if (url.pathname === '/oidc/.well-known/openid-configuration') {
    return Response.json({
      issuer: ISSUER,
      authorization_endpoint: `${ENDPOINT}/oidc/auth`,
      token_endpoint: `${ENDPOINT}/oidc/token`,
      jwks_uri: `${ENDPOINT}/oidc/jwks`,
      userinfo_endpoint: `${ENDPOINT}/oidc/me`,
      end_session_endpoint: `${ENDPOINT}/oidc/session/end`,
    })
  }

  if (url.pathname === '/oidc/jwks') {
    const { jwk } = await useTenantKeys()
    return Response.json({ keys: [jwk] })
  }

  if (url.pathname === '/oidc/token') {
    const parameters = new URLSearchParams(await request.text())

    if (parameters.get('grant_type') !== 'refresh_token') {
      return Response.json({ code: 'oidc.unsupported_grant_type', message: 'Unsupported' }, {
        status: 400,
      })
    }

    tenant.refreshGrants += 1

    const resource = parameters.get('resource') ?? ''
    const issuedAt = Math.floor(Date.now() / 1000)

    // A refresh grant returns a fresh ID token alongside the access token, which is what
    // makes the `roles` claim recoverable without signing out. The scopes are whatever
    // the tenant grants *now*, which is the reduced-grant case Logto documents.
    return Response.json({
      access_token: await mintAccessToken(resource, tenant.scopes),
      refresh_token: 'fixture-refresh-token',
      id_token: await mintIdToken(issuedAt, tenant.roles),
      scope: tenant.scopes.join(' '),
      token_type: 'Bearer',
      expires_in: TOKEN_TTL,
    })
  }
}
