export default defineEventHandler(async (event) => {
  // Ability-based guard. Equivalent to `requirePermission(event, 'assessment:view')`,
  // but the same object also drives `<Can>` in the template.
  await authorize(event, gates.viewAssessment)
  return { ok: true }
})
