function resolveBindings (options) {
  if (navigator.bluetooth && !process.env.NOBLE_WEBSOCKET) {
    return new (require('./webbluetooth/bindings'))(options);
  }

  return new (require('./websocket/bindings'))(options);
}

module.exports = resolveBindings;
