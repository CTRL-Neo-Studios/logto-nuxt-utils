export default defineEventHandler(async (event) => {
  // `requirePermission` is auto-imported by the module, and the permission
  // argument is typed as the literal union inferred from `rbac.config.ts` —
  // passing an unknown string here is a compile error.
  //
  // It returns the Logto user claims, matching `useServerLogtoUser(event)` but
  // non-nullable, since reaching this line proves there is a user.
  const user = await requirePermission(event, 'assessment:view')

  // Scopes are an access-token claim, so they are read from the context, not the
  // user. The guard already resolved it, and it is memoised per request.
  const { scopes } = await useAuthContext(event)

  return { ok: true, userId: user.sub, scopes }
})
