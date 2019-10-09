const createAuthenticationUrl = (jwt) => `egendata://account/${jwt}`

module.exports = {
  createAuthenticationUrl
}
