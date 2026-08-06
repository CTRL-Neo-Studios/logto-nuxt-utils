import { PERMISSIONS } from './rbac'

export default defineNuxtConfig({
  modules: ['@logto/nuxt', '@type32/logto-nuxt-utils'],

  devtools: { enabled: true },
  compatibilityDate: 'latest',

  /**
   * Only connection details here. `scopes` and `resources` are deliberately absent:
   * the module derives both from `logtoRbac` below, which is the whole point.
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

  logtoRbac: {
    /**
     * Must be an API resource that actually exists in your Logto console.
     *
     * Logto validates this as an RFC 8707 `resource` parameter on the authorization
     * request, so an unregistered indicator fails sign-in with
     * `invalid_target: resource indicator is missing, or unknown`.
     */
    resources: [
      process.env.NUXT_LOGTO_API_RESOURCE || 'https://playground.example.com/api/v1',
    ],
    /**
     * Each of these must exist as a permission on the resource above, otherwise Logto
     * rejects the request with `invalid_scope`.
     */
    permissions: [...PERMISSIONS],
  },
})
