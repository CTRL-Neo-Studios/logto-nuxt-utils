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
      callback: '/api/auth/callback',
    },
    postCallbackRedirectUri: '/',
  },

  logtoRbac: {
    resources: ['https://playground.example.com/api/v1'],
    permissions: [...PERMISSIONS],
  },
})
