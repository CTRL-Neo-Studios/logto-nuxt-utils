import LogtoRbacModule from '../../../src/module'

export default defineNuxtConfig({
  modules: ['@logto/nuxt', LogtoRbacModule],

  // Credentials only. `scopes` and `resources` are deliberately absent: the module
  // derives them from `logtoRbac`, which is what the tests assert.
  logto: {
    endpoint: 'https://fixture.logto.test',
    appId: 'fixture-app-id',
    appSecret: 'fixture-app-secret',
    cookieEncryptionKey: 'fixture-cookie-encryption-key',
  },

  logtoRbac: {
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
  },
})
