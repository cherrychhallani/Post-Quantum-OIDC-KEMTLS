// connection.js
const net = require("net");
const { encodeFrame, parseFrames } = require("./framing");
const { clientHandshake } = require("./MyKeyEstablishment");
// Removed "onceFrame" require - not needed anymore

const connections = new Map();

function createConnectionAPI(mySelf, onMessage) {

  // Helper to standard message handling
  function handleMessage(fromPeerId, payload, socket) {
    if (onMessage) {
        onMessage(fromPeerId, payload, socket);
    } else {
        console.log(
          `[${mySelf.id}] Received from ${fromPeerId}: ${payload.toString()}`
        );
    }
  }

  async function EstablishConnect(destination) {
    const peerId = destination.id;
    let entry = connections.get(peerId);

    if (entry && !entry.socket.destroyed) {
      return entry.socket;
    }

    // 1. Create Socket
    const socket = net.createConnection({
      host: destination.host,
      port: destination.port
    });

    // Wait for TCP connection to open
    await new Promise(res => socket.once("connect", res));
    console.log(`[${mySelf.id}] Connected to ${peerId}. Starting Handshake...`);

    // 2. PHASE 1: KEM-TLS HANDSHAKE (Blocking)
    // We do this BEFORE setting up the standard frame parser
    let establishedSSK = null;
    try {
      await clientHandshake(socket, (ssk) => {
        establishedSSK = ssk;
      });
    } catch (err) {
      console.error(`[${mySelf.id}] Handshake Error with ${peerId}:`, err.message);
      socket.destroy();
      throw err;
    }

    // ===============================================
    //  ADD THIS BLOCK HERE TO PRINT THE KEY
    // ===============================================
    console.log(`[${mySelf.id}] Secure Session Established with ${peerId}`);
    console.log(`[${mySelf.id}] Session Key: ${establishedSSK.toString("hex").substring(0, 20)}...`); 
    // ===============================================

    // 3. PHASE 2: REGISTER CONNECTION & START LISTENING
    // Clean up KEM listeners so they don't interfere with normal traffic
    socket.removeAllListeners("data");

    entry = {
      socket,
      buffer: Buffer.alloc(0),
      ssk: establishedSSK, // Store the key we just agreed on
      sskState: "ESTABLISHED"
    };

    connections.set(peerId, entry);

    // Now start the standard frame parser
    socket.on("data", data => {
      parseFrames(entry, data, payload => {
        handleMessage(peerId, payload, socket);
      });
    });

    socket.on("close", () => connections.delete(peerId));
    socket.on("error", () => connections.delete(peerId));

    // 4. Send Identity (Securely, post-handshake)
    // The server is waiting for this frame now
    socket.write(encodeFrame(Buffer.from(mySelf.id)));

    return socket;
  }

  async function GetSSK(destination) {
    const peerId = destination.id;
    
    // EstablishConnect now handles the handshake automatically
    if (!connections.has(peerId)) {
      await EstablishConnect(destination);
    }
    
    return connections.get(peerId).ssk;
  }

  function SendRaw(socket, buffer) {
    return new Promise(resolve => {
      socket.write(encodeFrame(buffer), resolve);
    });
  }

  return {
    EstablishConnect,
    GetSSK,
    SendRaw,
    connections
  };
}

module.exports = { createConnectionAPI };