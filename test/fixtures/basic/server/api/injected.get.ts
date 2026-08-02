/**
 * Surfaces what the module injected, for assertions.
 *
 * `owned` are the resources accepted as an inbound `aud` and used for permissions;
 * `requested` is everything asked for at sign-in, including other services'.
 */
export default defineEventHandler((event) => {
  const logto = (useRuntimeConfig() as unknown as Record<string, {
    scopes?: string[]
    resources?: string[]
  }>).logto ?? {}

  return {
    scopes: logto.scopes ?? [],
    requested: logto.resources ?? [],
    owned: useOwnedResources(event),
  }
})
