import type { ObjectPlugin, Plugin } from 'nuxt/app'
import type { ClientAuthContext } from '../../types'
import {
  defineNuxtPlugin,
  useRequestFetch,
  useRuntimeConfig,
  useState,
} from '#imports'

/**
 * What this plugin injects into the Nuxt app.
 *
 * A type alias rather than an interface, so it picks up an implicit index
 * signature and therefore satisfies `defineNuxtPlugin`'s
 * `Record<string, unknown>` constraint.
 */
type AuthorizationInjections = {
  authorization: {
    resolveClientUser: () => Promise<ClientAuthContext | null>
  }
}

/**
 * Explicit annotation required by `mkdist` when emitting declarations: the type
 * inferred from `defineNuxtPlugin` cannot be named without referencing Nuxt's
 * internal `Plugin` / `ObjectPlugin` (TS2883).
 */
type AuthorizationResolverPlugin
  = Plugin<AuthorizationInjections> & ObjectPlugin<AuthorizationInjections>

/**
 * Feeds `nuxt-authorization` the current user on the client.
 *
 * Resolving from the session endpoint is necessary rather than merely convenient:
 * `useLogtoUser()` exposes ID-token claims, which contain role names at best and
 * no permissions at all, because permissions only exist inside the access token
 * held in an httpOnly cookie.
 *
 * The result is cached in `useState`, so it is fetched once during SSR and
 * hydrated into the client instead of being re-requested on every navigation or
 * ability check.
 */
const plugin: AuthorizationResolverPlugin = defineNuxtPlugin({
  name: 'logto-rbac:authorization-resolver',
  parallel: true,
  setup() {
    const endpoint = useRuntimeConfig().public.logtoRbac.sessionEndpoint
    const context = useState<ClientAuthContext | null>('logto-rbac:auth-context', () => null)

    // Forwards the incoming cookies during SSR. A plain `$fetch` would omit the
    // session cookie and therefore always resolve to unauthenticated on the server.
    const requestFetch = useRequestFetch()

    let pending: Promise<ClientAuthContext | null> | null = null

    async function resolve(): Promise<ClientAuthContext | null> {
      // Prerendering has no request-bound user. Resolving here would bake an
      // anonymous context into static HTML and, because the result is cached in
      // `useState` and hydrated, that anonymous verdict would then stick on the
      // client forever — permissions would silently never appear. Defer to the
      // client instead, where the real session cookie is available.
      if (import.meta.prerender) return null

      if (context.value) return context.value

      // Collapse concurrent ability checks into a single request.
      pending ??= requestFetch<ClientAuthContext>(endpoint)
        .then((result) => {
          context.value = result
          return result
        })
        .catch((error) => {
          console.warn('[logto-rbac] Failed to resolve client auth context:', error)
          return null
        })
        .finally(() => {
          pending = null
        })

      return pending
    }

    return {
      provide: {
        authorization: {
          // `null` for guests, so abilities without `allowGuest` deny by default.
          resolveClientUser: async () => {
            const ctx = await resolve()
            return ctx?.isAuthenticated ? ctx : null
          },
        },
      },
    }
  },
})

export default plugin
