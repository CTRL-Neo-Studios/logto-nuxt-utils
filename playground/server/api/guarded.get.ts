export default defineEventHandler(async (event) => {
  // `requirePermission` is auto-imported by the module, and the permission
  // argument is typed as the literal union inferred from `rbac.config.ts` —
  // passing an unknown string here is a compile error.
  const ctx = await requirePermission(event, 'assessment:view')

  return { ok: true, userId: ctx.userId, scopes: ctx.scopes }
})
