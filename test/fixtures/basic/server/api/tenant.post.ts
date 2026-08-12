import { defineEventHandler, readBody, setCookie } from 'h3'
import { wrapSession } from '@logto/node'
import { mintAccessToken, mintIdToken, tenant } from '../utils/tenant'

interface TenantRequest {
  /** Replaces what the tenant grants, standing in for an edit in the Logto console. */
  roles?: string[]
  scopes?: string[]
  /** Issues a session cookie for the fixture user. */
  signIn?: {
    /**
     * Seconds to backdate the session by.
     *
     * Ages both the tokens and the module's own freshness marker, which is how a session
     * past `revalidateAfter` is produced without making the test wait it out.
     */
    age?: number
    /**
     * Whether to seed the module's bookkeeping at all.
     *
     * `false` reproduces a session created before this feature existed, or one that has
     * just come back from the sign-in callback: no record, nothing known about its grant.
     */
    withRecord?: boolean
    /** Cached access tokens, as a session that has already resolved once would hold. */
    withAccessTokens?: boolean
    /**
     * The permission list the session was granted, when it differs from the configured
     * one — which is the state of a live session after a new permission is deployed.
     */
    grantedPermissions?: string[]
  }
  /** Resets the counter, so a test can attribute refresh grants to its own requests. */
  resetGrants?: boolean
}

/**
 * The fixture's control surface: acts as both the Logto console and the sign-in callback.
 *
 * Writing the cookie here rather than driving a real authorization flow is what keeps the
 * test offline, but its contents are the genuine article — `wrapSession` is Logto's own
 * AES-GCM wrapper, the tokens are signed by the tenant and verified by `@logto/client`,
 * and the bookkeeping is written through the module's own `fingerprintPermissions`. So
 * everything downstream of the cookie is the shipped code path.
 */
export default defineEventHandler(async (event) => {
  const body = await readBody<TenantRequest>(event) ?? {}
  const config = useRuntimeConfig(event)

  if (body.roles) tenant.roles = body.roles
  if (body.scopes) tenant.scopes = body.scopes
  if (body.resetGrants) tenant.refreshGrants = 0

  if (body.signIn) {
    const {
      age = 0,
      withRecord = true,
      withAccessTokens = true,
      grantedPermissions,
    } = body.signIn

    const issuedAt = Math.floor(Date.now() / 1000) - age
    const owned = useOwnedResources(event)

    // Keyed as `@logto/client` keys them: the sorted scope list, empty here, then `@` and
    // the resource indicator (`buildAccessTokenKey`).
    const accessTokens = Object.fromEntries(await Promise.all(owned.map(async resource => [
      `@${resource}`,
      {
        token: await mintAccessToken(resource, tenant.scopes),
        scope: tenant.scopes.join(' '),
        // A full hour ahead, so the cache is never invalidated by expiry: anything that
        // changes did so because this module discarded it.
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      },
    ])))

    const record = {
      issuedAt,
      fetchedAt: issuedAt,
      fingerprint: fingerprintPermissions(grantedPermissions ?? config.logtoRbac.permissions),
    }

    const session = {
      idToken: await mintIdToken(issuedAt, tenant.roles),
      refreshToken: 'fixture-refresh-token',
      ...(withAccessTokens && { accessToken: JSON.stringify(accessTokens) }),
      ...(withRecord && { 'logtoRbac:grant': JSON.stringify(record) }),
    }

    const logto = config.logto as unknown as {
      cookieName?: string
      cookieEncryptionKey: string
    }

    setCookie(
      event,
      logto.cookieName ?? 'logtoCookies',
      await wrapSession(session, logto.cookieEncryptionKey),
      { httpOnly: true, path: '/', sameSite: 'lax', maxAge: 14 * 24 * 3600 },
    )
  }

  return { roles: tenant.roles, scopes: tenant.scopes, refreshGrants: tenant.refreshGrants }
})
