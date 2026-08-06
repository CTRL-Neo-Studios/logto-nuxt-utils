import type { H3Event } from 'h3'
import type { AuthContext } from '../../types'
import { describeLogtoOidcError, formatLogtoOidcError } from '../../shared/diagnostics'
import { useAuthContext } from '../utils/verify'

/** The contract `nuxt-authorization`'s server bouncer reads off the event context. */
interface AuthorizationEventContext {
  resolveServerUser: () => Promise<AuthContext | null>
}

/**
 * The slice of Nitro's app object this plugin uses.
 *
 * Declared locally rather than imported from `nitropack/runtime`, since
 * `defineNitroPlugin` is only an identity helper and Nitro simply invokes the
 * default export. Avoiding the import keeps the module free of a direct dependency
 * on Nitro's runtime entry point, which has moved between versions.
 */
interface NitroAppLike {
  hooks: {
    hook: ((event: 'request', callback: (event: H3Event) => void) => void)
      & ((event: 'error', callback: (error: unknown) => void) => void)
  }
}

/**
 * Supplies `nuxt-authorization` with the server-side user.
 *
 * Its server bouncer (`allows` / `denies` / `authorize`) reads
 * `event.context.$authorization.resolveServerUser()`, and the module itself ships
 * only a client-side counterpart, so without this every server-side ability check
 * fails.
 *
 * Three deliberate design points:
 *
 * 1. **Lazy.** The resolver is a closure that only touches Logto when an ability is
 *    actually evaluated. Resolving eagerly in this hook would add a cookie decrypt,
 *    and potentially a network round-trip, to every single request — including ones
 *    that never authorize anything. It would also interfere with Logto's own
 *    sign-in / sign-out / callback routes, which issue redirects.
 *
 * 2. **Fails closed.** `nuxt-authorization`'s `authorize()` catches errors and
 *    rethrows only its own `AuthorizationError`; anything else is swallowed and the
 *    route proceeds *as though authorized*. A throwing resolver would therefore be
 *    an authorization bypass, so every failure maps to `null`.
 *
 * 3. **`null` for guests**, rather than an anonymous context object, because
 *    `defineAbility` treats a `null` user as an automatic denial unless the ability
 *    opted into `allowGuest`.
 */
async function resolveServerUser(event: H3Event): Promise<AuthContext | null> {
  try {
    const ctx = await useAuthContext(event)
    return ctx.isAuthenticated ? ctx : null
  }
  catch (error) {
    console.warn('[logto-rbac] resolveServerUser failed; denying by default:', error)
    return null
  }
}

export default (nitro: NitroAppLike) => {
  nitro.hooks.hook('request', (event) => {
    // Assigned through a cast rather than relying on `nuxt-authorization`'s own
    // `H3EventContext` augmentation, which types the resolver as a generic
    // `<User>() => Promise<User | null>` that no concrete implementation can
    // satisfy structurally.
    ;(event.context as Record<string, unknown>).$authorization = {
      resolveServerUser: () => resolveServerUser(event),
    } satisfies AuthorizationEventContext
  })

  /**
   * Explains Logto's OIDC errors instead of letting them surface as bare codes.
   *
   * The sign-in callback is handled by `@logto/nuxt`'s own route, so a
   * misconfiguration here throws from inside that handler with no reference to the
   * config that caused it — `invalid_target` in particular reads as "resource
   * indicator is missing, or unknown", which gives no clue that it means an entry in
   * `logtoRbac.resources` is not registered in Logto.
   *
   * This only logs; the response is left entirely to Nitro.
   */
  nitro.hooks.hook('error', (error) => {
    const info = describeLogtoOidcError(error)
    if (info) console.error(`[logto-rbac] ${formatLogtoOidcError(info)}\n`)
  })
}
