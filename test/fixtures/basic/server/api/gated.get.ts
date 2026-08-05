/** Guarded by an ability rather than by `requirePermission`. */
export default defineEventHandler(async (event) => {
  await authorize(event, gates.viewAssessment)
  return { ok: true }
})
