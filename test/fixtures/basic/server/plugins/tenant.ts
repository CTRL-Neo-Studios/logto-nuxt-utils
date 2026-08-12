import LogtoClient from '@logto/node'
import { jwtVerify } from 'jose'
import { APP_ID, ENDPOINT, handleTenantRequest, ISSUER, useTenantKeys } from '../utils/tenant'

/**
 * Points `@logto/client` at the in-process tenant.
 *
 * Two interceptions are needed, for two different transports:
 *
 * - Discovery and the token endpoint go through the `fetch` that `@logto/node` hands the
 *   client at construction, which it offers no seam for replacing, so the global is
 *   shimmed. Only requests whose origin is the configured Logto endpoint — a host that
 *   does not resolve — are claimed; the rest are delegated, leaving Nitro's own fetching
 *   untouched.
 * - ID-token verification goes through `jose`'s `createRemoteJWKSet`, which captures its
 *   own fetch reference and so would try to resolve that host for real. The fixture *is*
 *   the tenant, so verifying against its key directly is equivalent to fetching a JWKS
 *   that would publish only that key.
 */
export default defineNitroPlugin(() => {
  const original = globalThis.fetch

  globalThis.fetch = async (input, init) => {
    const request = new Request(input as RequestInfo, init)

    if (new URL(request.url).origin === ENDPOINT) {
      // Cloned because the handler reads the body, and a miss must leave the request
      // intact for the real `fetch` below.
      const response = await handleTenantRequest(request.clone())
      if (response) return response
    }

    return original(input, init)
  }

  // Installed on the prototype because `@logto/nuxt`'s handler constructs a client per
  // request and exposes no point between construction and first use.
  Object.defineProperty(LogtoClient.prototype, 'jwtVerifier', {
    configurable: true,
    get: () => ({
      verifyIdToken: async (idToken: string) => {
        const { publicKey } = await useTenantKeys()
        await jwtVerify(idToken, publicKey, { audience: APP_ID, issuer: ISSUER })
      },
    }),
  })
})
