const { token } = require('@egendata/messaging')
const { JWT, JWK } = require('@panva/jose')
const {
  emitter,

  SIGN_START,
  SIGN,
  SIGN_ERROR,

  VERIFY_START,
  VERIFY,
  VERIFY_ERROR
} = require('./events.js')

const { decode, sign, verify } = token({
  sign: (payload, key, header) => {
    emitter.emit(SIGN_START)
    try {
      const result = JWT.sign(payload, JWK.asKey(key), { header })
      emitter.emit(SIGN)
      return result
    } catch (error) {
      emitter.emit(SIGN_ERROR, error)
      throw error
    }
  },
  decode: (tok, opts) => {
    const { payload, header, signature } = JWT.decode(tok, opts)
    return { claimsSet: payload, header, signature }
  },
  verify: (tok, jwk) => {
    emitter.emit(VERIFY_START)
    try {
      const result = JWT.verify(tok, JWK.asKey(jwk))
      emitter.emit(VERIFY)
      return result
    } catch (error) {
      emitter.emit(VERIFY_ERROR, error)
      throw error
    }
  }
})

module.exports = {
  decode,
  verify,
  sign
}
