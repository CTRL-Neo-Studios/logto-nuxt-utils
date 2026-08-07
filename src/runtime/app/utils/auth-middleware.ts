import type { RouteMiddleware } from 'nuxt/app'
import type { AuthRequirements } from '../../shared/requirements'
import { useAuthorization } from '../composables/useAuthorization'
import {
  abortNavigation,
  createError,
  defineNuxtRouteMiddleware,
  navigateTo,
  useRuntimeConfig,
} from '#imports'

export interface AuthMiddlewareOptions extends AuthRequirements {
  /**
   * Where to send an unauthenticated visitor.
   *
   * Defaults to the Logto sign-in path configured in `nuxt.config`.
   */
  redirectTo?: string
  /**
   * Send unauthenticated visitors to `redirectTo` rather than aborting.
   *
   * Set to `false` to make a missing session a 401 like any other failure, which suits
   * routes reached programmatically rather than by navigation.
   *
   * @default true
   */
  redirectUnauthenticated?: boolean
}

/**
 * Builds a route middleware enforcing declarative requirements.
 *
 * The client-side counterpart to `requireLogtoUser`, using the very same checks, so a
 * page guard cannot drift from the route handler behind it.
 *
 * @example
 * ```ts
 * // app/middleware/assessment-editor.ts
 * export default defineAuthMiddleware({ permissions: ['assessment:edit'] })
 * ```
 *
 * @example
 * ```ts
 * // Applied to a single page
 * definePageMeta({ middleware: defineAuthMiddleware({ anyPermission: ['a', 'b'] }) })
 * ```
 */
export function defineAuthMiddleware(options: AuthMiddlewareOptions = {}): RouteMiddleware {
  const { redirectTo, redirectUnauthenticated = true, ...requirements } = options

  return defineNuxtRouteMiddleware(async () => {
    // A prerendered page has no request-bound user, so there is nothing to authorize
    // and no cookie to read. Gating here would bake one visitor's verdict into static
    // HTML served to everyone.
    if (import.meta.prerender) return

    const auth = useAuthorization()
    await auth.resolve()

    if (!auth.isAuthenticated.value && redirectUnauthenticated) {
      const target = redirectTo
        ?? useRuntimeConfig().public.logtoRbac.signInPath

      return navigateTo(target, { external: true })
    }

    if (auth.satisfies(requirements)) return

    const authenticated = auth.isAuthenticated.value

    return abortNavigation(createError({
      status: authenticated ? 403 : 401,
      statusText: authenticated ? 'Forbidden' : 'Unauthorized',
      message: authenticated
        ? 'You do not have permission to view this page.'
        : 'Authentication required.',
    }))
  })
}
