/**
 * Client-side route guard.
 *
 * The counterpart to `requireLogtoUser` on the server, using the same requirement
 * checks so the page guard cannot drift from the route handler behind it.
 */
export default defineAuthMiddleware({
  permissions: ['assessment:edit'],
})
