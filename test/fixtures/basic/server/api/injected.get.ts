/**
 * Surfaces what the module injected, for assertions.
 *
 * `owned` are the resources accepted as an inbound `aud` and used for permissions;
 * `requested` is everything asked for at sign-in, including other services'.
 *
 * `revalidateAfter` is read from both runtime configs because they serve different
 * readers: the server expires its resource tokens on the private one, the browser
 * expires its cached verdict on the public one.
 */
export default defineEventHandler((event) => {
  const config = useRuntimeConfig(event)
  const logto = (config as unknown as Record<string, {
    scopes?: string[]
    resources?: string[]
  }>).logto ?? {}

  return {
    scopes: logto.scopes ?? [],
    requested: logto.resources ?? [],
    owned: useOwnedResources(event),
    revalidateAfter: config.logtoRbac.revalidateAfter,
    publicRevalidateAfter: config.public.logtoRbac.revalidateAfter,
  }
})
