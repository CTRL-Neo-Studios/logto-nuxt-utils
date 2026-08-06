import { computed, type ComputedRef, type Ref } from 'vue'
import type { ClientAuthContext, Permission } from '../../types'
import {
  type AuthRequirements,
  checkRequirements,
} from '../../shared/requirements'
import {
  useRequestFetch,
  useRuntimeConfig,
  useState,
} from '#imports'

/**
 * Reactive access to the current user's roles and permissions on the client.
 *
 * The browser structurally cannot determine its own permissions — they live in the
 * `scope` claim of an access token inside an httpOnly cookie — so this resolves them
 * from the session endpoint and caches the result in `useState`, meaning it is fetched
 * once during SSR and hydrated rather than re-requested on every navigation.
 *
 * The same checks the server runs are reused verbatim, so a rule cannot drift between
 * the UI and the route that enforces it.
 */
export interface UseAuthorizationReturn {
  /** The resolved context, or `null` when unauthenticated or not yet fetched. */
  user: Ref<ClientAuthContext | null>
  isAuthenticated: ComputedRef<boolean>
  /** Permissions held, i.e. the granted scopes. */
  scopes: ComputedRef<string[]>
  /** Role names held. Empty for callers whose token carries none. */
  roles: ComputedRef<string[]>
  /** Ensures the context has been fetched, returning it. */
  resolve: () => Promise<ClientAuthContext | null>
  /** Discards the cached context and fetches it again. */
  refresh: () => Promise<ClientAuthContext | null>
  /** True when every listed permission is held. The common case. */
  can: (...permissions: Permission[]) => boolean
  /** True when at least one listed permission is held. */
  canAny: (...permissions: Permission[]) => boolean
  /** True when at least one listed role is held, matched exactly. */
  hasRole: (...roles: string[]) => boolean
  /** Full declarative check, identical to the server's. */
  satisfies: (requirements?: AuthRequirements) => boolean
}

const STATE_KEY = 'logto-rbac:auth-context'

/**
 * Tracks the in-flight request so concurrent callers share one fetch.
 *
 * Module-scoped rather than per-call, since several components and abilities may all
 * ask for the context during the same tick.
 */
let pending: Promise<ClientAuthContext | null> | null = null

export function useAuthorization(): UseAuthorizationReturn {
  const endpoint = useRuntimeConfig().public.logtoRbac.sessionEndpoint
  const user = useState<ClientAuthContext | null>(STATE_KEY, () => null)

  // Forwards the incoming cookies during SSR. A plain `$fetch` would omit the session
  // cookie and therefore always resolve to unauthenticated on the server.
  const requestFetch = useRequestFetch()

  async function fetchContext(): Promise<ClientAuthContext | null> {
    pending ??= requestFetch<ClientAuthContext>(endpoint)
      .then((result) => {
        user.value = result
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

  async function resolve(): Promise<ClientAuthContext | null> {
    // Prerendering has no request-bound user. Resolving would bake an anonymous
    // context into static HTML and, because the result is cached in `useState` and
    // hydrated, that verdict would then stick on the client forever — permissions
    // would silently never appear. Defer to the client, where the cookie exists.
    if (import.meta.prerender) return null

    if (user.value) return user.value
    return fetchContext()
  }

  async function refresh(): Promise<ClientAuthContext | null> {
    user.value = null
    pending = null
    return resolve()
  }

  /**
   * Cast because `AuthContext` carries `claims` while the client deliberately does
   * not receive them. Only `verified` reads claims, and an absent value counts as
   * verified, so the check degrades exactly as it does for a bearer caller.
   */
  const check = (requirements?: AuthRequirements) =>
    checkRequirements(user.value as never, requirements).ok

  return {
    user,
    isAuthenticated: computed(() => user.value?.isAuthenticated ?? false),
    scopes: computed(() => user.value?.scopes ?? []),
    roles: computed(() => user.value?.roles ?? []),
    resolve,
    refresh,
    can: (...permissions) => check({ permissions }),
    canAny: (...permissions) => check({ anyPermission: permissions }),
    hasRole: (...roles) => check({ roles }),
    satisfies: requirements => check(requirements),
  }
}
