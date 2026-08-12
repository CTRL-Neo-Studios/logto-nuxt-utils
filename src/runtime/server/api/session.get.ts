import { defineEventHandler } from 'h3'
import type { ClientAuthContext } from '../../types'
import { useSessionAuthContext } from '../utils/auth-context'

/**
 * Exposes the current user's roles and permissions to the browser.
 *
 * This endpoint exists because the client structurally *cannot* determine its own
 * permissions: they live in the `scope` claim of an access token held inside an
 * httpOnly, encrypted cookie. Without a server round-trip there is no way for
 * `<Can>` / `<Bouncer>` or any client-side ability to know what the user may do.
 *
 * Deliberately resolves the session context only. A bearer token is a
 * service-to-service concern and has no business driving UI state. Tokens and raw
 * claims are stripped; only the normalised decision inputs are returned.
 */
export default defineEventHandler(async (event): Promise<ClientAuthContext> => {
  const ctx = await useSessionAuthContext(event)

  return {
    isAuthenticated: ctx.isAuthenticated,
    source: ctx.source,
    userId: ctx.userId,
    roles: ctx.roles,
    scopes: ctx.scopes,
    organizations: ctx.organizations,
    organizationRoles: ctx.organizationRoles,
    profile: ctx.profile,
    isVerified: ctx.isVerified,
    needsReauthorization: ctx.needsReauthorization,
  }
})
