/**
 * Permission gates.
 *
 * `shared/utils/` is auto-imported by Nuxt into both the app and the server, so the
 * same ability object drives `<Can>` in templates and `authorize(event, …)` in route
 * handlers. Files at the `shared/` root are *not* auto-imported — they need
 * `#shared/…` — which is why this lives under `utils/`.
 */
export const gates = definePermissionGates({
  viewAssessment: 'assessment:view',
  listAssessments: 'assessment:list',
  manageAssessment: ['assessment:edit', 'assessment:delete'],
  reviewAssessment: { anyPermission: ['assessment:edit', 'assessment:share'] },
  verifiedEditor: { permissions: ['assessment:edit'], verified: true },
  admin: { roles: ['Admin'] },
})

/** An override permission standing in for a real ownership check. */
export const editOrAdmin = anyOfAbilities(gates.manageAssessment, gates.admin)
