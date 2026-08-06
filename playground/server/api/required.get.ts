/**
 * Declarative requirements on the server.
 *
 * One call replaces an authentication check plus a permission check plus the
 * hand-written 401/403 throwing that usually accompanies them.
 */
export default defineEventHandler(async (event) => {
  const ctx = await requireUser(event, {
    permissions: ['assessment:view'],
    anyPermission: ['assessment:edit', 'assessment:share'],
  })

  return { ok: true, userId: ctx.userId, scopes: ctx.scopes }
})
