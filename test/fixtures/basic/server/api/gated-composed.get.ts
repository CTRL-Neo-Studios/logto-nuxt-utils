/** Guarded by a composed ability, to prove combinators work over HTTP too. */
export default defineEventHandler(async (event) => {
  await authorize(event, viewOrAdmin)
  return { ok: true }
})
