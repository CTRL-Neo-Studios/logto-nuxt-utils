// Imported by package name deliberately, so the path real consumers take is
// exercised at runtime. Works even with a stubbed `dist/` because the module
// registers a jiti alias for this specifier when loading the config.
import { defineRbacConfig } from '@type32/logto-nuxt-utils/config'

export default defineRbacConfig({
  // Two owned resources, to cover permission unioning across resources.
  resources: [
    'https://fixture.example.com/api/v1',
    'https://fixture.example.com/reports/v1',
  ],

  // Requested so the app can call another service, but never a valid inbound
  // audience and never a source of this app's own permissions.
  additionalResources: [
    { resource: 'https://sibling.example.com/api/v1', scopes: ['sibling:read'] },
  ],

  permissions: [
    'assessment:view',
    'assessment:edit',
  ],
})
