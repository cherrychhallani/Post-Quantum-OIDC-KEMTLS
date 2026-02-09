function encodeFrame(buffer) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buffer.length);
  return Buffer.concat([len, buffer]);
}

function parseFrames(state, data, onFrame) {
  state.buffer = Buffer.concat([state.buffer, data]);

  while (state.buffer.length >= 4) {
    const len = state.buffer.readUInt32BE(0);
    if (state.buffer.length < 4 + len) break;

    const payload = state.buffer.slice(4, 4 + len);
    state.buffer = state.buffer.slice(4 + len);

    onFrame(payload);
  }
}

module.exports = {
  encodeFrame,
  parseFrames
};
