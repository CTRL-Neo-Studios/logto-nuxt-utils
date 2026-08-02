/**
 * Permission catalogue.
 *
 * Kept in its own file purely for readability — no framework helper is involved,
 * it is spread into `logtoRbac.permissions` in `nuxt.config.ts`.
 */
export const PERMISSIONS = [
  'assessment:create',
  'assessment:view',
  'assessment:list',
  'assessment:test',
  'assessment:delete',
  'assessment:share',
  'assessment:edit',
] as const
