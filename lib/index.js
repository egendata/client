const { createMemoryStore } = require('./memoryStore')

module.exports = {
  create: require('./client'),
  events: require('./events'),
  utils: {
    createMemoryStore
  }
}
