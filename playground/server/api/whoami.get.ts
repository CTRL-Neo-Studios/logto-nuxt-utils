/**
 * Returns whoever is calling, resolved from either a session cookie or a verified
 * bearer token. Useful for eyeballing what the module actually sees.
 */
export default defineEventHandler(async (event) => {
  return await useAuthContext(event)
})
