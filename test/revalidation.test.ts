import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { fetch, setup } from '@nuxt/test-utils/e2e'

interface Session {
  isAuthenticated: boolean
  roles: string[]
  scopes: string[]
  needsReauthorization?: boolean
}

interface TenantState {
  roles: string[]
  scopes: string[]
  refreshGrants: number
}

/** Mirrors the fixture's own `signIn` payload; see `server/api/tenant.post.ts`. */
interface SignInOptions {
  age?: number
  withRecord?: boolean
  withAccessTokens?: boolean
  grantedPermissions?: string[]
}

/** The fixture's `revalidateAfter`, so a session older than this is due for revalidation. */
const WINDOW = 60

/**
 * Signs the fixture user in and returns the session cookie to present on later requests.
 *
 * `age` backdates the session, which is how one past the freshness window is produced
 * without a sleep.
 */
async function signIn(signInOptions: SignInOptions = {}): Promise<string> {
  const response = await fetch('/api/tenant', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ signIn: signInOptions, resetGrants: true }),
  })

  const cookie = response.headers.getSetCookie()
    .find(value => value.startsWith('logtoCookies='))

  expect(cookie, 'the fixture must issue a session cookie').toBeDefined()
  return cookie!.split(';')[0]!
}

/**
 * Resolves the session context as the browser would, carrying `cookie`.
 *
 * Returns the context *and* any refreshed cookie, because revalidation rewrites the
 * session — dropping it would resend a stale one and retest the same first request.
 */
async function resolve(cookie: string): Promise<{ session: Session, cookie: string }> {
  const response = await fetch('/api/_auth/session', { headers: { cookie } })
  const session = await response.json() as Session
  const updated = response.headers.getSetCookie()
    .find(value => value.startsWith('logtoCookies='))

  return { session, cookie: updated ? updated.split(';')[0]! : cookie }
}

/** Edits the tenant the way an administrator would edit the Logto console. */
async function updateTenant(changes: { roles?: string[], scopes?: string[] }): Promise<void> {
  await fetch('/api/tenant', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(changes),
  })
}

async function tenantState(): Promise<TenantState> {
  return await (await fetch('/api/tenant')).json() as TenantState
}

/**
 * End-to-end proof that a signed-in session picks up RBAC changes.
 *
 * The fixture runs a real OIDC tenant in-process — discovery, JWKS and the token endpoint
 * — and seeds a genuine encrypted session cookie, so `@logto/client` performs its actual
 * refresh grant against it. Nothing here stubs this module's own code; a passing
 * assertion means the shipped path works.
 */
describe('session revalidation', async () => {
  await setup({
    rootDir: fileURLToPath(new URL('./fixtures/basic', import.meta.url)),
  })

  it('resolves a seeded session from its cached token, without contacting the tenant', async () => {
    const cookie = await signIn()
    const { session } = await resolve(cookie)

    // The baseline every other case is measured against: a fresh session is served from
    // the cookie's own cache, which is the behaviour `revalidateAfter` must not disturb.
    expect(session.isAuthenticated).toBe(true)
    expect(session.roles).toEqual(['editor'])
    expect(session.scopes).toContain('assessment:view')
    expect((await tenantState()).refreshGrants).toBe(0)
  })

  it('keeps serving a revoked permission inside the freshness window', async () => {
    const cookie = await signIn()
    await updateTenant({ scopes: ['assessment:view'] })

    const { session } = await resolve(cookie)

    // Deliberately asserted: revalidating on every request would cost a refresh-token
    // exchange per resource per request. The window is the whole point of the trade.
    expect(session.scopes).toContain('assessment:edit')
    expect((await tenantState()).refreshGrants).toBe(0)
  })

  it('drops a revoked permission once the window has passed', async () => {
    // Older than `revalidateAfter`, but the cached access token is still valid for an
    // hour — so anything that changes here changed because the cache was discarded.
    const cookie = await signIn({ age: WINDOW + 5 })
    await updateTenant({ scopes: ['assessment:view'] })

    const { session } = await resolve(cookie)

    expect(session.scopes).not.toContain('assessment:edit')
    expect(session.scopes).toContain('assessment:view')
    expect((await tenantState()).refreshGrants).toBeGreaterThan(0)
  })

  it('restores a permission that is granted again, so revalidation is not one-way', async () => {
    const cookie = await signIn({ age: WINDOW + 5 })
    await updateTenant({ scopes: ['assessment:view'] })

    const revoked = await resolve(cookie)
    expect(revoked.session.scopes).not.toContain('assessment:edit')

    await updateTenant({ scopes: ['assessment:view', 'assessment:edit'] })

    // The session it revalidated into is itself fresh, so age it again.
    const aged = await signIn({ age: WINDOW + 5 })
    const restored = await resolve(aged)

    expect(restored.session.scopes).toContain('assessment:edit')
  })

  it('picks up a removed role without signing out', async () => {
    const cookie = await signIn({ age: WINDOW + 5 })
    await updateTenant({ roles: [] })

    const { session } = await resolve(cookie)

    // Roles come from the ID token, which `@logto/nuxt`'s handler captured before any
    // refresh could run. Reading them from the token the refresh grant returned is what
    // makes this work; before that, only signing out did.
    expect(session.roles).toEqual([])
  })

  it('does not revalidate again on the request that follows one', async () => {
    const cookie = await signIn({ age: WINDOW + 5 })

    const first = await resolve(cookie)
    const grantsAfterFirst = (await tenantState()).refreshGrants
    expect(grantsAfterFirst).toBeGreaterThan(0)

    await resolve(first.cookie)

    // The freshness marker has to survive in the rewritten cookie; if it did not, every
    // request would perform a fresh refresh grant per resource.
    expect((await tenantState()).refreshGrants).toBe(grantsAfterFirst)
  })

  it('adopts a session that carries no record of its grant', async () => {
    // A session created before this feature existed, or one that has just returned from
    // the sign-in callback. Nothing is known about what it was granted, so reporting it
    // stale would nag every user once on upgrade.
    const cookie = await signIn({ withRecord: false })
    const { session } = await resolve(cookie)

    expect(session.needsReauthorization).toBe(false)
  })

  it('reports a grant that predates the configured permission list', async () => {
    // Granted a narrower list than the fixture configures, which is the state of every
    // live session the moment a new permission is deployed. A refresh grant cannot fix
    // it — Logto issues only scopes from the original authorization request — so the
    // flag is the whole remedy.
    const cookie = await signIn({ grantedPermissions: ['assessment:view'] })
    const stale = await resolve(cookie)

    expect(stale.session.needsReauthorization).toBe(true)

    // Even revalidating cannot clear it: the grant itself is what is short.
    const aged = await signIn({ age: WINDOW + 5, grantedPermissions: ['assessment:view'] })
    const revalidated = await resolve(aged)

    expect(revalidated.session.needsReauthorization).toBe(true)

    // A new authorization request — what `reauthorize()` triggers — is what clears it.
    const reauthorized = await resolve(await signIn())
    expect(reauthorized.session.needsReauthorization).toBe(false)
  })

  it('performs the refresh grant when no cached token is available', async () => {
    const cookie = await signIn({ withAccessTokens: false })
    const { session } = await resolve(cookie)

    // Nothing to serve from the cookie, so the scopes can only have come from a live
    // exchange with the tenant.
    expect(session.scopes).toContain('assessment:view')
    expect((await tenantState()).refreshGrants).toBeGreaterThan(0)
  })
})
