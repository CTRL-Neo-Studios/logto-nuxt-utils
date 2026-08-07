import type { H3Event } from 'h3'
import { createError } from 'h3'
// Type-only import purely to pull in `@logto/nuxt`'s `H3EventContext`
// augmentation, which is what gives `event.context.logtoClient` / `.logtoUser`
// their types. Erased at build time.
import type {} from '@logto/nuxt'
import { logtoEventHandler } from '#logto'
import { useRuntimeConfig } from '#imports'

/**
 * The Logto Node client, inferred from the context augmentation shipped by
 * `@logto/nuxt` so this never drifts from the installed version's surface.
 */
export type ServerLogtoClient = H3Event['context']['logtoClient']
export type ServerLogtoUser = H3Event['context']['logtoUser']

/**
 * The Logto user claims, guaranteed present.
 *
 * The guards in `authorize.ts` return this rather than the nullable
 * {@link ServerLogtoUser}: they have already established that the caller is
 * authenticated, so handing back something possibly-`undefined` would push a null
 * check onto every call site for a case the guard just ruled out.
 */
export type ServerLogtoUserClaims = NonNullable<ServerLogtoUser>

/**
 * Tracks the in-flight `logtoEventHandler` call for each request.
 *
 * The handler does real work: it constructs a client, decrypts the cookie
 * storage and, when `fetchUserInfo` is enabled, performs a network round-trip to
 * the userinfo endpoint. Calling it once per helper would make a single request
 * pay for all of that repeatedly.
 *
 * Caching the *promise* rather than the result also collapses concurrent callers
 * into a single execution. A `WeakMap` keyed by the event keeps this strictly
 * per-request and avoids adding bookkeeping keys to `event.context`.
 */
const pendingHandlers = new WeakMap<H3Event, Promise<void>>()

/** Ensures Logto has populated `event.context` exactly once for this request. */
function ensureLogtoContext(event: H3Event): Promise<void> {
  const pending = pendingHandlers.get(event)
  if (pending) return pending

  // Cast because the shape Nuxt generates for `runtimeConfig.logto` depends on the
  // consuming app's own config, so it cannot be relied on structurally here.
  const promise = logtoEventHandler(event, useRuntimeConfig(event) as { logto: unknown })
  pendingHandlers.set(event, promise)
  return promise
}

/**
 * Resolves the Logto client for the current request.
 *
 * @throws When the handler claimed the response instead of populating the
 * context. That happens on the configured `signIn` / `signOut` / `callback`
 * pathnames, where it issues a redirect and returns early, so calling this from
 * those routes is a programming error rather than an auth failure.
 */
export async function useServerLogtoClient(event: H3Event): Promise<ServerLogtoClient> {
  await ensureLogtoContext(event)

  const client = event.context.logtoClient
  if (!client) {
    throw createError({
      status: 500,
      statusText: 'Internal Server Error',
      message: 'Logto client unavailable. This route is handled directly by Logto '
        + '(sign-in, sign-out or callback), so it has no request context.',
    })
  }

  return client
}

/**
 * Returns the current user's token claims, or `undefined` when unauthenticated.
 *
 * With `fetchUserInfo: false` (the recommended setting, and this module's
 * default) these are the **ID token** claims, read straight from the session
 * cookie at no network cost. That includes `roles` — which is an ID-token claim,
 * not a userinfo-only one — plus `email`, `name`, `picture` and `username`.
 *
 * It does *not* include `custom_data` or `identities`; see
 * {@link useServerLogtoUserInfo}.
 */
export async function useServerLogtoUser(event: H3Event): Promise<ServerLogtoUser> {
  await ensureLogtoContext(event)
  return event.context.logtoUser
}

/** True when the request carries a valid Logto session. */
export async function isServerLogtoAuthenticated(event: H3Event): Promise<boolean> {
  const client = await useServerLogtoClient(event)
  return client.isAuthenticated()
}

/**
 * Explicitly fetches the userinfo endpoint for the claims the ID token omits
 * (`custom_data`, `identities`, `organization_data`).
 *
 * Costs one HTTP round-trip per call, which is exactly why it is opt-in rather
 * than running on every request. Returns `undefined` instead of throwing, so a
 * failed profile fetch cannot take down a route.
 */
export async function useServerLogtoUserInfo(event: H3Event) {
  const client = await useServerLogtoClient(event)

  if (!(await client.isAuthenticated())) return undefined

  try {
    return await client.fetchUserInfo()
  }
  catch (error) {
    console.warn('[logto-rbac] Failed to fetch userinfo:', error)
    return undefined
  }
}
