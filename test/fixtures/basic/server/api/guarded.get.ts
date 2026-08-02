export default defineEventHandler(async (event) => {
  await requirePermission(event, 'assessment:view')
  return { ok: true }
})
