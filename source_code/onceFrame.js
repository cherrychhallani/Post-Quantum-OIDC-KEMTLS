// onceFrame.js
const { parseFrames } = require("./framing");

function onceFrame(socket, state, callback) {
  function onData(data) {
    parseFrames(state, data, payload => {
      socket.off("data", onData);
      callback(payload);
    });
  }

  socket.on("data", onData);
}

module.exports = { onceFrame };
