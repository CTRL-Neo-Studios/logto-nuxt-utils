import LogtoRbacModule from '../../../src/module'

export default defineNuxtConfig({
  modules: ['@logto/nuxt', LogtoRbacModule],

  // Credentials only. `scopes` and `resources` are deliberately absent: the module
  // derives them from `rbac.config.ts`, which is what the tests assert.
  logto: {
    endpoint: 'https://fixture.logto.test',
    appId: 'fixture-app-id',
    appSecret: 'fixture-app-secret',
    cookieEncryptionKey: 'fixture-cookie-encryption-key',
  },
})
