/**
 * Gates live in `shared/utils/` so Nuxt auto-imports them into both the app and the
 * server — the same ability object is then used by `<Can>` and by
 * `authorize(event, …)`.
 */
export const gates = definePermissionGates({
  viewAssessment: 'assessment:view',
  manageAssessment: ['assessment:view', 'assessment:edit'],
  reviewAssessment: { anyPermission: ['assessment:edit'] },
  verifiedViewer: { permissions: ['assessment:view'], verified: true },
  admin: { roles: ['Admin'] },
})

/** Composition across gates, exercised over HTTP by the fixture routes. */
export const viewOrAdmin = anyOfAbilities(gates.viewAssessment, gates.admin)
