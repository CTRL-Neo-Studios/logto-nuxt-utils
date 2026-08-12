import { defineEventHandler } from 'h3'
import { tenant } from '../utils/tenant'

/** Reports what the tenant granted and how many refresh grants it has served. */
export default defineEventHandler(() => ({
  roles: tenant.roles,
  scopes: tenant.scopes,
  refreshGrants: tenant.refreshGrants,
}))
