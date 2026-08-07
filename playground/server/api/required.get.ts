/**
 * Declarative requirements on the server.
 *
 * One call replaces an authentication check plus a permission check plus the
 * hand-written 401/403 throwing that usually accompanies them.
 */
export default defineEventHandler(async (event) => {
  // Returns the Logto user claims, like `useServerLogtoUser` but non-nullable.
  const user = await requireLogtoUser(event, {
    permissions: ['assessment:view'],
    anyPermission: ['assessment:edit', 'assessment:share'],
  })

  // Permissions live in an access token's `scope` claim, never in the ID token, so
  // they come from the context rather than the user. Memoised per request, so this
  // costs nothing after the guard above already resolved it.
  const { scopes } = await useAuthContext(event)

  return { ok: true, userId: user.sub, email: user.email, scopes }
})
