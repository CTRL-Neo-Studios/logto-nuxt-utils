import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { $fetch, fetch, setup } from '@nuxt/test-utils/e2e'

interface Injected {
  scopes: string[]
  requested: string[]
  owned: string[]
  revalidateAfter: number
  publicRevalidateAfter: number
}

const OWNED = [
  'https://fixture.example.com/api/v1',
  'https://fixture.example.com/reports/v1',
]
const ADDITIONAL = 'https://sibling.example.com/api/v1'

describe('logto-nuxt-utils', async () => {
  await setup({
    rootDir: fileURLToPath(new URL('./fixtures/basic', import.meta.url)),
  })

  describe('config derivation', () => {
    it('derives logto scopes and resources from rbac.config.ts', async () => {
      const injected = await $fetch<Injected>('/api/injected')

      // The whole point of the module: declared once in rbac.config.ts and never
      // restated in nuxt.config.
      expect(injected.scopes).toContain('assessment:view')
      expect(injected.scopes).toContain('assessment:edit')
      expect(injected.owned).toEqual(OWNED)
    })

    it('always requests the roles scope, since roles are otherwise absent', async () => {
      const injected = await $fetch<Injected>('/api/injected')

      // Without `roles`, the claim is `undefined` rather than an empty array.
      expect(injected.scopes).toContain('roles')
      expect(injected.scopes).toContain('email')
      expect(injected.scopes).toContain('profile')
    })

    it('requests additional resources and their scopes', async () => {
      const injected = await $fetch<Injected>('/api/injected')

      // A token must be obtainable for another service, so it has to be requested.
      expect(injected.requested).toContain(ADDITIONAL)
      expect(injected.scopes).toContain('sibling:read')
    })

    it('does not emit duplicate scopes', async () => {
      const { scopes } = await $fetch<Injected>('/api/injected')
      expect(scopes).toHaveLength(new Set(scopes).size)
    })

    it('publishes revalidateAfter to both the server and the browser', async () => {
      const injected = await $fetch<Injected>('/api/injected')

      // The server expires resource tokens on the private value; the browser expires its
      // cached verdict on the public one. A missing public value would leave the client
      // serving a stale context forever even though the server had refreshed it.
      expect(injected.revalidateAfter).toBe(60)
      expect(injected.publicRevalidateAfter).toBe(60)
    })
  })

  describe('audience separation', () => {
    it('excludes additional resources from the accepted audience', async () => {
      const injected = await $fetch<Injected>('/api/injected')

      // The security-relevant assertion: another service's resource is requested so
      // this app can call it, but is never a valid `aud` for tokens arriving here.
      // Were it accepted, a token minted for that service could be replayed against
      // this one, and overlapping scope names would satisfy permission checks it was
      // never intended for.
      expect(injected.requested).toContain(ADDITIONAL)
      expect(injected.owned).not.toContain(ADDITIONAL)
    })

    it('never treats an additional resource as a permission source', async () => {
      // `sibling:read` is granted for the other service, but must not appear as one
      // of this app's own permissions.
      const session = await $fetch<{ scopes: string[] }>('/api/_auth/session')
      expect(session.scopes).not.toContain('sibling:read')
    })
  })

  describe('session endpoint', () => {
    it('reports an anonymous context when unauthenticated', async () => {
      const session = await $fetch('/api/_auth/session')

      expect(session).toMatchObject({
        isAuthenticated: false,
        source: 'anonymous',
        roles: [],
        scopes: [],
      })
    })

    it('never leaks raw token claims to the client', async () => {
      const session = await $fetch<Record<string, unknown>>('/api/_auth/session')
      expect(session).not.toHaveProperty('claims')
    })

    it('does not claim an anonymous caller needs re-authorization', async () => {
      // The flag describes a session grant, and an anonymous caller has none. Reporting
      // `true` here would prompt visitors who have never signed in to "reconnect".
      const session = await $fetch<Record<string, unknown>>('/api/_auth/session')
      expect(session.needsReauthorization).toBeUndefined()
    })

    it('publishes the profile and the resolved verified verdict', async () => {
      // Without these the browser has no user to render and, since it never receives
      // `claims`, no way to evaluate the `verified` requirement the server enforces.
      const session = await $fetch<Record<string, unknown>>('/api/_auth/session')

      expect(session.profile).toEqual({
        sub: null,
        name: null,
        username: null,
        email: null,
        emailVerified: false,
        phoneNumber: null,
        phoneNumberVerified: false,
        picture: null,
      })
      expect(session.isVerified).toBe(true)
    })
  })

  describe('guards', () => {
    it('rejects an unauthenticated caller with 401', async () => {
      const response = await fetch('/api/guarded')
      expect(response.status).toBe(401)
    })

    it('rejects a malformed bearer token rather than falling back to anonymous', async () => {
      // A caller that attempted to authenticate and failed must not be silently
      // downgraded to a guest.
      const response = await fetch('/api/guarded', {
        headers: { authorization: 'Bearer not-a-real-jwt' },
      })

      expect(response.status).toBe(401)
    })
  })

  describe('abilities', () => {
    it('rejects an unauthenticated caller through an ability with 401, not 403', async () => {
      // Proves the whole chain: gates auto-imported from shared/utils, the nitro
      // plugin resolving the server user, and the ability reporting 401 rather than
      // nuxt-authorization's default 403 for a guest.
      const response = await fetch('/api/gated')
      expect(response.status).toBe(401)
    })

    it('applies composed abilities over HTTP', async () => {
      const response = await fetch('/api/gated-composed')
      expect(response.status).toBe(401)
    })
  })

  describe('declarative requirements', () => {
    it('rejects an unauthenticated caller with 401', async () => {
      const response = await fetch('/api/required')
      expect(response.status).toBe(401)
    })

    it('reports which requirement failed', async () => {
      // The machine-readable payload is what lets a client distinguish "sign in" from
      // "you are missing assessment:view".
      const response = await fetch('/api/required')
      const body = await response.json() as { data?: { failed?: string } }

      expect(body.data?.failed).toBe('unauthenticated')
    })
  })

  describe('client utilities', () => {
    it('renders the client surface for an anonymous visitor', async () => {
      // SSR-rendered rather than mocked: this is the only proof that the composables
      // resolve through the real session endpoint and that both Logto pathnames reach
      // the browser through public runtime config.
      const html = await $fetch<string>('/')

      expect(html).toContain('<p id="can-view">false</p>')
      // Always a string, so a template never has to spell out a fallback.
      expect(html).toContain('<p id="display-name">Guest</p>')
      // Present and null-filled, not `undefined`.
      expect(html).toContain('<p id="profile-name"></p>')
      expect(html).toContain('<p id="sign-in-path">/enter</p>')
      expect(html).toContain('<p id="sign-out-path">/leave</p>')
      expect(html).toContain('<p id="source">anonymous</p>')
      // The guards' machine-readable verdict, available client-side too.
      expect(html).toContain('<p id="failed">unauthenticated</p>')
      // Regresses if `useCan`'s prefetch or the per-app pending state is wrong.
      expect(html).toContain('<p id="ready">true</p>')
    })
  })
})
