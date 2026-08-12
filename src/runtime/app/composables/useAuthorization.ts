import { computed, type ComputedRef, ref, type Ref } from 'vue'
import type { NuxtApp } from 'nuxt/app'
import type {
  AuthContext,
  AuthSource,
  ClientAuthContext,
  LogtoUserProfile,
  Permission,
} from '../../types'
import {
  type AuthRequirements,
  checkRequirements,
  type RequirementResult,
} from '../../shared/requirements'
import {
  ctxHasOrganizationRole,
  ctxMissingPermissions,
  profileFromClaims,
} from '../../shared/core'
import {
  useNuxtApp,
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
  /**
   * The Logto user, always an object: `profile.name` needs no optional chaining, and
   * every field is `string | null` rather than `string | null | undefined`.
   */
  profile: ComputedRef<LogtoUserProfile>
  /**
   * A label that is always a `string`, for the common "greet the user" case.
   *
   * Precedence: `name`, `username`, `email`, `phoneNumber`, `sub`. Falls back to
   * `'Guest'`, which is reachable only when nobody is signed in, since `sub` is always
   * present for an authenticated caller.
   */
  displayName: ComputedRef<string>
  /** How the context was established. `'anonymous'` before resolution. */
  source: ComputedRef<AuthSource>
  /** Logto user id (`sub`), or `null`. */
  userId: ComputedRef<string | null>
  /** Organization ids the user belongs to. */
  organizations: ComputedRef<string[]>
  /** True while a resolve is in flight. */
  pending: Ref<boolean>
  /** Message of the last failed resolve, retried on the client after an SSR failure. */
  error: Ref<string | null>
  /** True once a verdict exists, so a `false` from `can()` means "no" and not "not yet". */
  ready: ComputedRef<boolean>
  /**
   * True when this session's grant predates the current permission list, so some
   * configured permissions can never appear in its tokens. Call
   * `useLogtoSession().reauthorize()` to fix it.
   */
  needsReauthorization: ComputedRef<boolean>
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
  /** The subset of `permissions` the user lacks, for actionable messages. */
  missingPermissions: (...permissions: Permission[]) => Permission[]
  /** True when the user belongs to the organization. */
  isOrganizationMember: (organizationId: string) => boolean
  /** True when the user holds one of `roles` within the organization. */
  hasOrganizationRole: (organizationId: string, ...roles: string[]) => boolean
  /** Full verdict, with `failed` / `required` / `held`, mirroring the guards' payload. */
  explain: (requirements?: AuthRequirements) => RequirementResult
}

const STATE_KEY = 'logto-rbac:auth-context'

/**
 * The profile handed to every unauthenticated caller.
 *
 * Actually frozen, not frozen by convention: this single instance is shared, so a
 * consumer mutating `profile.value.name` would otherwise corrupt every other reader.
 * All fields are primitives, so a shallow freeze is total.
 */
const ANONYMOUS_PROFILE: Readonly<LogtoUserProfile> = Object.freeze(profileFromClaims(undefined))

interface AuthRequestState {
  /** In-flight fetch, so concurrent callers in one app instance share one request. */
  pending: Promise<ClientAuthContext | null> | null
  isPending: Ref<boolean>
  /** Message of the last failed resolve. Never serialised, so the client retries. */
  error: Ref<string | null>
  /** Whether a verdict has been obtained at least once in this app instance. */
  resolved: Ref<boolean>
  /**
   * Epoch-ms of the last successful resolve, used to expire the cached verdict.
   *
   * `null` until one completes in this app instance, which includes the hydrated case:
   * the server sends the context but no timestamp for it.
   */
  resolvedAt: number | null
}

/**
 * Resolution state per Nuxt app instance.
 *
 * Module scope is shared by every concurrent SSR request, which would let one visitor's
 * in-flight context resolve into another's rendered HTML. A `WeakMap` keyed by the app
 * instance is per-request on the server and a singleton on the client, and retains
 * nothing once a request ends.
 */
const requestStates = new WeakMap<NuxtApp, AuthRequestState>()

function useRequestState(nuxtApp: NuxtApp): AuthRequestState {
  let state = requestStates.get(nuxtApp)
  if (!state) {
    state = {
      pending: null,
      isPending: ref(false),
      error: ref(null),
      resolved: ref(false),
      resolvedAt: null,
    }
    requestStates.set(nuxtApp, state)
  }
  return state
}

export function useAuthorization(): UseAuthorizationReturn {
  const endpoint = useRuntimeConfig().public.logtoRbac.sessionEndpoint
  const user = useState<ClientAuthContext | null>(STATE_KEY, () => null)
  const state = useRequestState(useNuxtApp())

  // Forwards the incoming cookies during SSR. A plain `$fetch` would omit the session
  // cookie and therefore always resolve to unauthenticated on the server.
  const requestFetch = useRequestFetch()

  async function fetchContext(): Promise<ClientAuthContext | null> {
    if (!state.pending) {
      state.isPending.value = true
      state.error.value = null

      state.pending = requestFetch<ClientAuthContext>(endpoint)
        .then((result) => {
          user.value = result
          state.resolvedAt = Date.now()
          return result
        })
        .catch((error) => {
          console.warn('[logto-rbac] Failed to resolve client auth context:', error)
          state.error.value = error instanceof Error ? error.message : String(error)
          return null
        })
        .finally(() => {
          state.pending = null
          state.isPending.value = false
          state.resolved.value = true
        })
    }

    return state.pending
  }

  async function resolve(): Promise<ClientAuthContext | null> {
    // Prerendering has no request-bound user. Resolving would bake an anonymous
    // context into static HTML and, because the result is cached in `useState` and
    // hydrated, that verdict would then stick on the client forever — permissions
    // would silently never appear. Defer to the client, where the cookie exists.
    if (import.meta.prerender) return null

    const { revalidateAfter } = useRuntimeConfig().public.logtoRbac
    // A hydrated payload arrives with no client-side timestamp; treat it as resolved at
    // hydration time rather than immediately stale, otherwise every page load would
    // refetch a context the server just sent.
    state.resolvedAt ??= Date.now()

    const isFresh = revalidateAfter <= 0
      || Date.now() - state.resolvedAt < revalidateAfter * 1000

    if (user.value && isFresh) return user.value
    // A completed fetch leaves `pending` null already, but an in-flight one must not be
    // reused for a revalidation: it would return the very verdict being expired.
    if (user.value) state.pending = null

    return fetchContext()
  }

  async function refresh(): Promise<ClientAuthContext | null> {
    user.value = null
    state.pending = null
    state.error.value = null
    state.resolved.value = false
    state.resolvedAt = null
    return resolve()
  }

  /**
   * Cast because `AuthContext` carries `claims` while the client deliberately does not
   * receive them. Nothing depends on them here: `verified` reads the `isVerified` flag
   * the session endpoint resolved whenever `claims` are absent.
   */
  const ctx = (): AuthContext | null => user.value as AuthContext | null
  const check = (requirements?: AuthRequirements) => checkRequirements(ctx(), requirements).ok

  const profile = computed(() => user.value?.profile ?? ANONYMOUS_PROFILE)

  return {
    user,
    isAuthenticated: computed(() => user.value?.isAuthenticated ?? false),
    scopes: computed(() => user.value?.scopes ?? []),
    roles: computed(() => user.value?.roles ?? []),
    profile,
    displayName: computed(() => {
      const p = profile.value
      return p.name ?? p.username ?? p.email ?? p.phoneNumber ?? p.sub ?? 'Guest'
    }),
    source: computed(() => user.value?.source ?? 'anonymous'),
    // Read from `profile` so `userId` and `profile.sub` can never disagree.
    userId: computed(() => profile.value.sub),
    organizations: computed(() => user.value?.organizations ?? []),
    needsReauthorization: computed(() => user.value?.needsReauthorization ?? false),
    pending: state.isPending,
    error: state.error,
    // The second disjunct matters because a hydrated payload populates `user` while the
    // fresh client-side `resolved` ref is still `false`.
    ready: computed(() => state.resolved.value || user.value !== null),
    resolve,
    refresh,
    can: (...permissions) => check({ permissions }),
    canAny: (...permissions) => check({ anyPermission: permissions }),
    hasRole: (...roles) => check({ roles }),
    satisfies: requirements => check(requirements),
    missingPermissions: (...permissions) => ctxMissingPermissions(ctx(), ...permissions),
    isOrganizationMember: id => user.value?.organizations.includes(id) ?? false,
    hasOrganizationRole: (id, ...roles) => ctxHasOrganizationRole(ctx(), id, ...roles),
    explain: requirements => checkRequirements(ctx(), requirements),
  }
}
