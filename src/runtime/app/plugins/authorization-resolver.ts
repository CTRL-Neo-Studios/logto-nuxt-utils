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
  setup(nuxtApp) {
    // A consumer plugin that ran first already owns `$authorization`. Nuxt's
    // `provide` uses a non-configurable `Object.defineProperty`, so returning a
    // `provide` block here would throw `Cannot redefine property`. Yield instead:
    // whoever resolves the user first wins, and the build-time check in the module
    // has already warned about the duplicate.
    //
    // `Object.hasOwn` rather than `in`: `nuxt-authorization` declares
    // `$authorization` as always present on `NuxtApp`, so `in` would narrow the
    // remaining body to `never`. It is also the accurate test — Nuxt's `provide`
    // defines an own property, never an inherited one.
    if (Object.hasOwn(nuxtApp, '$authorization')) return

    const auth = useAuthorization()

    // Defined directly rather than via the returned `provide` block so the
    // descriptor can be `configurable`, letting a consumer plugin that runs *after*
    // this one override it instead of crashing.
    const authorization = {
      // `null` for guests, so abilities without `allowGuest` deny by default.
      resolveClientUser: async () => {
        const ctx = await auth.resolve()
        return ctx?.isAuthenticated ? ctx : null
      },
    }

    for (const target of [nuxtApp, nuxtApp.vueApp.config.globalProperties]) {
      Object.defineProperty(target, '$authorization', {
        get: () => authorization,
        configurable: true,
      })
    }
  },
})

export default plugin
