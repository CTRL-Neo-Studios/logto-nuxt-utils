import type { ObjectPlugin, Plugin } from 'nuxt/app'
import type { ClientAuthContext } from '../../types'
import { useAuthorization } from '../composables/useAuthorization'
import { defineNuxtPlugin } from '#imports'

/**
 * Feeds `nuxt-authorization` the current user on the client.
 *
 * Resolving from the session endpoint is necessary rather than merely convenient:
 * `useLogtoUser()` exposes ID-token claims, which contain role names at best and no
 * permissions at all, because permissions only exist inside the access token held in
 * an httpOnly cookie.
 *
 * The fetch itself lives in {@link useAuthorization}, so abilities, your own
 * components and this plugin all share one cached, de-duplicated request.
 */
type AuthorizationInjections = {
  authorization: {
    resolveClientUser: () => Promise<ClientAuthContext | null>
  }
}

/**
 * Explicit annotation required by `mkdist` when emitting declarations: the type
 * inferred from `defineNuxtPlugin` cannot be named without referencing Nuxt's internal
 * `Plugin` / `ObjectPlugin` (TS2883).
 */
type AuthorizationResolverPlugin =
  Plugin<AuthorizationInjections> & ObjectPlugin<AuthorizationInjections>

const plugin: AuthorizationResolverPlugin = defineNuxtPlugin({
  name: 'logto-rbac:authorization-resolver',
  parallel: true,
  setup() {
    const auth = useAuthorization()

    return {
      provide: {
        authorization: {
          // `null` for guests, so abilities without `allowGuest` deny by default.
          resolveClientUser: async () => {
            const ctx = await auth.resolve()
            return ctx?.isAuthenticated ? ctx : null
          },
        },
      },
    }
  },
})

export default plugin
