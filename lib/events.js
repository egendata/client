const { EventEmitter } = require('events')

module.exports = {
  emitter: new EventEmitter(),

  CONNECT_TO_OPERATOR_START: 'connect-to-operator-start',
  CONNECT_TO_OPERATOR: 'connect-to-operator',
  CONNECT_TO_OPERATOR_ERROR: 'connect-to-operator-error',

  DATA_READ_START: 'data-read-start',
  DATA_READ: 'data-read',
  DATA_READ_ERROR: 'data-read-error',

  DATA_WRITE_START: 'data-write-start',
  DATA_WRITE: 'data-write',
  DATA_WRITE_ERROR: 'data-write-error',

  ENCRYPT_START: 'encrypt-start',
  ENCRYPT: 'encrypt',
  ENCRYPT_ERROR: 'encrypt-error',

  DECRYPT_START: 'decrypt-start',
  DECRYPT: 'decrypt',
  DECRYPT_ERROR: 'decrypt-error',

  GENERATE_KEY_START: 'generate-key-start',
  GENERATE_KEY: 'generate-key',
  GENERATE_KEY_ERROR: 'generate-key-error',

  LOGIN: 'login',

  MESSAGE_RECIEVE_START: 'message-recieve-start',
  MESSAGE_RECIEVE: 'message-recieve',
  MESSAGE_RECIEVE_ERROR: 'message-recieve-error',

  MESSAGE_SEND_START: 'message-send-start',
  MESSAGE_SEND: 'message-send',
  MESSAGE_SEND_ERROR: 'message-send-error',

  SIGN_START: 'sign-start',
  SIGN: 'sign',
  SIGN_ERROR: 'sign-error',

  VERIFY_START: 'verify-start',
  VERIFY: 'verify',
  VERIFY_ERROR: 'verify-error'
}
