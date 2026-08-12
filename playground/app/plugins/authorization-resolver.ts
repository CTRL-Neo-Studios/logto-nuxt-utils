export default defineNuxtPlugin({
  name: 'consumer-authorization-resolver',
  setup() {
    return {
      provide: {
        authorization: {
          resolveClientUser: async () => ({ id: 'consumer-user' }),
        },
      },
    }
  },
})
