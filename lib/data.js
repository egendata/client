const { JWS, JWE, JWK } = require('@panva/jose')
const { verify } = require('./jwt')
const {
  emitter,

  DATA_READ_START,
  DATA_READ,
  DATA_READ_ERROR,

  DATA_WRITE_START,
  DATA_WRITE,
  DATA_WRITE_ERROR,

  ENCRYPT_START,
  ENCRYPT,
  ENCRYPT_ERROR,

  DECRYPT_START,
  DECRYPT,
  DECRYPT_ERROR,

  SIGN_START,
  SIGN,
  SIGN_ERROR
} = require('./events')

const read = (config, keyProvider, tokens) => async (connectionId, ...paths) => {
  emitter.emit(DATA_READ_START, { paths })

  try {
    // Default domain to clients own
    const withDomain = paths.map(({ domain, area }) => {
      domain = domain || config.clientId
      return { domain, area }
    })

    // Send token to operator
    const token = await tokens.createReadDataToken(connectionId, withDomain)
    const responseToken = await tokens.send(`${config.operator}/api`, token)

    // Parse the response token
    const { payload: response } = await verify(responseToken)

    // If no data, return undefined
    if (!response.paths) {
      return undefined
    }

    // Iterate through the paths
    const result = []
    for (let { domain, area, data } of response.paths) {
      try {
        let decryptedData
        if (data) {
          // Find the correct decryption key
          const rxServiceKey = new RegExp(`^${config.jwksURI}/`)
          const decryptionKeyId = data.recipients
            .map((recipient) => recipient.header.kid)
            .find((kid) => rxServiceKey.test(kid))
          const decryptionKey = await keyProvider.getKey(decryptionKeyId)

          // Use the key to decrypt the content
          let decrypted
          try {
            emitter.emit(DECRYPT_START)
            decrypted = JWE.decrypt(data, JWK.asKey(decryptionKey))
            emitter.emit(DECRYPT)
          } catch (error) {
            emitter.emit(DECRYPT_ERROR, error)
            throw error
          }
          const jws = decrypted.toString('utf8')

          // TODO: Verify the signature
          const [, content] = jws.split('.')
          const clearText = Buffer.from(content, 'base64').toString('utf8')

          decryptedData = JSON.parse(clearText)
        }
        result.push({ domain, area, data: decryptedData })
      } catch (error) {
        result.push({ domain, area, error })
      }
    }
    emitter.emit(DATA_READ, { paths })

    return result
  } catch (error) {
    emitter.emit(DATA_READ_ERROR, error)
    throw error
  }
}

const write = (config, keyProvider, tokens) => async (connectionId, ...paths) => {
  emitter.emit(DATA_WRITE_START, { paths })
  try {
    // Iterate through all paths
    const encryptedPaths = []
    for (let { domain, area, data } of paths) {
      // Default domain to clients own
      domain = domain || config.clientId

      // Get signing key for specific domain and area (right now always use clientKey)
      const signingKey = JWK.asKey(await keyProvider.getSigningKey(domain, area))
      let signedData
      try {
        emitter.emit(SIGN_START)
        signedData = JWS.sign(JSON.stringify(data), signingKey, { kid: signingKey.kid })
        emitter.emit(SIGN)
      } catch (error) {
        emitter.emit(SIGN_ERROR, error)
        throw error
      }

      const encryptor = new JWE.Encrypt(signedData)

      const permissionJWKS = await keyProvider.getWriteKeys(domain, area)
      const writeKeys = permissionJWKS.keys.map((key) => JWK.asKey(key))
      for (let key of writeKeys) {
        encryptor.recipient(key, { kid: key.kid })
      }

      let encryptedData
      try {
        emitter.emit(ENCRYPT_START)
        encryptedData = encryptor.encrypt('general')
        emitter.emit(ENCRYPT)
      } catch (error) {
        emitter.emit(ENCRYPT_ERROR, error)
        throw error
      }

      encryptedPaths.push({
        domain,
        area,
        data: encryptedData
      }) // Only general serialization allowed for multiple recipients
    }

    const token = await tokens.createWriteDataToken(connectionId, encryptedPaths)
    const result = await tokens.send(`${config.operator}/api`, token)

    emitter.emit(DATA_WRITE, { paths })

    return result
  } catch (error) {
    emitter.emit(DATA_WRITE_ERROR, error)
    throw error
  }
}

const auth = (config, keyProvider, tokens) => (token) => {
  return {
    read: async (options) => {
      const { payload: { sub } } = await verify(token)
      return read(config, keyProvider, tokens)(sub, options)
    },
    write: async (options) => {
      const { payload: { sub } } = await verify(token)
      return write(config, keyProvider, tokens)(sub, options)
    }
  }
}

module.exports = ({ config, keyProvider, tokens }) => ({
  read: read(config, keyProvider, tokens),
  write: write(config, keyProvider, tokens),
  auth: auth(config, keyProvider, tokens)
})
