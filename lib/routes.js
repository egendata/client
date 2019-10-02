const { Router, json } = require('express')
const jwt = require('./jwt')
const { connectionInitHandler, connectionEventHandler } = require('./connection')
const { loginEventHandler } = require('./login')
const bodyParser = require('body-parser')
const { middleware: { signed } } = require('@egendata/messaging')
const {
  emitter,
  MESSAGE_RECIEVE_START,
  MESSAGE_RECIEVE,
  MESSAGE_RECIEVE_ERROR
} = require('./events')

const keyListHandler = ({ keyProvider }) => async (req, res, next) => {
  const keys = await keyProvider.jwksKeyList()
  res.send(keys)
}

const keyHandler = ({ keyProvider }) => async (req, res, next) => {
  const key = await keyProvider.jwksKey(req.params.kid)
  res.send(key)
}

const handlers = {
  CONNECTION_INIT: connectionInitHandler,
  CONNECTION_EVENT: connectionEventHandler,
  LOGIN_EVENT: loginEventHandler
}

module.exports = (client) => {
  const router = new Router()

  router.use(json())
  router.use(bodyParser.text({ type: 'application/jwt' }))

  router.get(client.config.jwksPath, keyListHandler(client))
  router.get(`${client.config.jwksPath}/:kid`, keyHandler(client))
  router.post(client.config.eventsPath,
    (req, _, next) => {
      try {
        const { claimsSet } = jwt.decode(req.body)
        emitter.emit(MESSAGE_RECIEVE_START, { type: claimsSet.type })
      } catch (_) {
      } finally { next() }
    },
    signed(jwt),
    async (req, res, next) => {
      if (!handlers[req.payload.type]) {
        const error = Error(`Missing handler for ${req.payload.type}`)
        emitter.emit(MESSAGE_RECIEVE_ERROR, error)
        return next(error)
      }
      emitter.emit(MESSAGE_RECIEVE, { type: req.payload.type })
      try {
        await handlers[req.payload.type](client)(req, res)
      } catch (error) {
        next(error)
      }
    }
  )

  return router
}
