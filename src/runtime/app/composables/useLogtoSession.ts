import { navigateTo, useRuntimeConfig } from '#imports'

export interface UseLogtoSessionReturn {
  /** Path that starts the Logto sign-in flow. */
  signInPath: string
  /** Path that starts the Logto sign-out flow. */
  signOutPath: string
  signIn: () => Promise<void>
  signOut: () => Promise<void>
}

/**
 * Sign-in and sign-out navigation for the browser.
 *
 * Logto's pathnames live in **private** runtime config, so the browser cannot discover
 * them; this module mirrors both into public config, which is why a template no longer
 * has to hardcode `/sign-in` and `/sign-out`.
 *
 * There is deliberately no `returnTo` argument: `@logto/nuxt`'s handler builds its
 * `redirectUri` from `pathnames.callback` and then redirects to the statically
 * configured `postCallbackRedirectUri`, ignoring query parameters — a per-call return
 * target could not be honoured, so accepting one would silently drop it.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * const session = useLogtoSession()
 * </script>
 *
 * <template>
 *   <button @click="session.signIn()">Sign in</button>
 * </template>
 * ```
 */
export function useLogtoSession(): UseLogtoSessionReturn {
  const { signInPath, signOutPath } = useRuntimeConfig().public.logtoRbac

  return {
    signInPath,
    signOutPath,
    // `external: true` is required: these are server routes owned by `@logto/nuxt`'s
    // event handler, not Vue routes, so the router must not try to resolve them.
    signIn: async () => {
      await navigateTo(signInPath, { external: true })
    },
    signOut: async () => {
      await navigateTo(signOutPath, { external: true })
    },
  }
}
