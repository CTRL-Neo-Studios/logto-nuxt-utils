export default defineNuxtConfig({
  modules: ['@logto/nuxt', '@type32/logto-nuxt-utils'],

  devtools: { enabled: true },
  compatibilityDate: 'latest',

  /**
   * Only the connection details live here. The permission list and API resource
   * come from `rbac.config.ts`, and the module derives `logto.scopes` and
   * `logto.resources` from it — that is the whole point of the module.
   */
  logto: {
    endpoint: process.env.NUXT_LOGTO_ENDPOINT || 'https://replace-me.logto.app',
    appId: process.env.NUXT_LOGTO_APP_ID || 'replace-me',
    appSecret: process.env.NUXT_LOGTO_APP_SECRET || 'replace-me',
    cookieEncryptionKey: process.env.NUXT_LOGTO_COOKIE_ENCRYPTION_KEY || 'replace-me',
    pathnames: {
      signIn: '/signin',
      signOut: '/signout',
      callback: '/api/v1/auth/callback',
    },
    postCallbackRedirectUri: '/',
  },

  logtoRbac: {},
})
