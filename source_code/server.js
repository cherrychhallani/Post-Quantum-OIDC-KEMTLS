// server.js
const net = require("net");
const { parseFrames } = require("./framing");
const { serverHandshake } = require("./MyKeyEstablishment");

// Removed "onceFrame" require - not needed anymore

function startServer(mySelf, connections, onMessage) {
  return new Promise(resolve => {
    // 1. Make this callback ASYNC
    const server = net.createServer(async (socket) => {
      let peerId = null;
      const state = { buffer: Buffer.alloc(0) };

      console.log(`[${mySelf.id}] Connection accepted. Starting KEM-TLS Handshake...`);

      // 2. PHASE 1: HANDSHAKE
      // We pause the standard 'parseFrames' logic. 
      // The handshake function will handle the socket directly.
      let establishedSSK = null;

      try {
        await serverHandshake(socket, (ssk) => {
          establishedSSK = ssk;
        });
      } catch (err) {
        console.error(`[${mySelf.id}] Handshake Error:`, err.message);
        socket.destroy();
        return;
      }

      // 3. PHASE 2: APPLICATION DATA
      // Handshake is done. Remove KEM listeners and start listening for Frames.
      socket.removeAllListeners("data");

      socket.on("data", data => {
        parseFrames(state, data, payload => {
          
          if (!peerId) {
            // The first frame AFTER handshake is the Peer ID
            peerId = payload.toString();

            connections.set(peerId, {
              socket,
              buffer: Buffer.alloc(0),
              ssk: establishedSSK, // We attach the key we established in Phase 1
              sskState: "ESTABLISHED"
            });

            console.log(`[${mySelf.id}] Secure Session Established with ${peerId}`);
            console.log(`[${mySelf.id}] Session Key: ${establishedSSK.toString("hex").substring(0, 20)}...`);

          } else {
            // Standard Message Handling (Preserved)
            if (onMessage) {
              onMessage(peerId, payload, socket);
            } else {
              console.log(
                `[${mySelf.id}] Received from ${peerId}: ${payload.toString()}`
              );
            }
          }
        });
      });

      socket.on("close", () => {
        if (peerId) connections.delete(peerId);
      });
      
      socket.on("error", (err) => console.log("Socket error:", err.message));
    });

    server.listen(mySelf.port, () => {
      console.log(`[${mySelf.id}] Listening on ${mySelf.port}`);
      resolve();
    });
  });
}

module.exports = { startServer };