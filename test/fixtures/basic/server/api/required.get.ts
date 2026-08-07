/** Declarative requirements via the composite guard. */
export default defineEventHandler(async (event) => {
  await requireLogtoUser(event, {
    permissions: ['assessment:view'],
    verified: true,
  })

  return { ok: true }
})
