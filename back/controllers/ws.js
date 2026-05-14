import { WebSocketServer, WebSocket } from 'ws';
import { Room } from '../models/db.js';

const activeRooms = new Map();
const webSocketController = {
  /**
   * Attaches the WebSocket server to the existing HTTP server.
   * Called once from server.js.
   * @param {import('http').Server} httpServer 
   */
  initWebSocket(httpServer) {
    const wss = new WebSocketServer({ noServer: true });
    // Handle HTTP upgrade requests to WebSocket protocol
    httpServer.on('upgrade', (request, socket, head) => {
      const url = new URL(request.url, `http://${request.headers.host}`);
      const roomName = url.searchParams.get('roomName');
      const token = url.searchParams.get('token');
      if (!roomName || !token) {
        socket.destroy();
        return;
      }
      wss.handleUpgrade(request, socket, head, (ws) => {
        webSocketController.handleConnection(ws, roomName, token);
      });
    });
    //console.log('✅ WebSocket server initialized (pure ws, 1:1 chat)');
  },

  /**
   * Validates the incoming connection and assigns the socket to host or joiner.
   */
  async handleConnection(ws, roomName, token) {
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room) {
        ws.close(4000, 'Room not found');
        return;
      }
      // Determine role
      let role = null;
      if (room.hostToken === token) role = 'host';
      else if (room.joinerToken === token) role = 'joiner';
      else {
        ws.close(4001, 'Invalid token');
        return;
      }
      // Chat must have started (secret already validated)
      if (!room.encryptedSecret) {
        ws.close(4002, 'Chat not started yet');
        return;
      }
      // Store the socket
      if (!activeRooms.has(roomName)) {
        activeRooms.set(roomName, { hostWS: null, joinerWS: null, lastMsgAt: null });
      }
      const roomSockets = activeRooms.get(roomName);
      roomSockets[`${role}WS`] = ws;
      //console.log(`🔌 ${role.toUpperCase()} connected to room ${roomName}`);
      // WebSocket events
      ws.on('close', () => {
        if (roomSockets[`${role}WS`] === ws) {
          roomSockets[`${role}WS`] = null;
        }
        const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
        if ((!roomSockets.hostWS && !roomSockets.joinerWS) &&
            (roomSockets.lastMsgAt && roomSockets.lastMsgAt < weekAgo)) {
          activeRooms.delete(roomName);
        }
      });

      ws.on('error', (err) => console.error('WebSocket error:', err));
      ws.on('message', (data) => {
        try {
          const msg = JSON.parse(data);
          if (msg.type === 'webrtc-signaling') {
            webSocketController.broadcastSignaling(roomName, msg.payload, role);
          }
        } catch (e) {
          console.error('Invalid WebSocket message:', e);
        }
      });
    } catch (e) {
      console.error('WebSocket connection error:', e);
      ws.close(4003, 'Server error');
    }
  },

  /**
   * Forwards an encrypted message to the other participant.
   * Called from the sendMessage functions in chat controller.
   * @param {string} roomName 
   * @param {object} messageObj - The object saved in DB
   * @param {string} sender - 'host' or 'joiner'
   */
  broadcastMessage(roomName, messageObj, sender) {
    const roomSockets = activeRooms.get(roomName);
    if (!roomSockets) return;

    roomSockets.lastMsgAt = Date.now(); 

    const receiverRole = sender === 'host' ? 'joiner' : 'host';
    const receiverWS = roomSockets[`${receiverRole}WS`];

    if (receiverWS && receiverWS.readyState === WebSocket.OPEN) {
      receiverWS.send(JSON.stringify(messageObj));
      //console.log(`📤 Encrypted message forwarded to ${receiverRole} in room ${roomName}`);
      return true;
    }
    return false;
  },

  broadcastSignaling(roomName, payload, senderRole) {
    const roomSockets = activeRooms.get(roomName);
    if (!roomSockets) return;

    const receiverRole = senderRole === 'host' ? 'joiner' : 'host';
    const receiverWS = roomSockets[`${receiverRole}WS`];

    if (receiverWS && receiverWS.readyState === WebSocket.OPEN) { //send the signaling to the other peer's WebSocket
      receiverWS.send(JSON.stringify({
        type: 'webrtc-signaling',
        payload
      }));
      //console.log(`📡 WebRTC signaling forwarded to ${receiverRole} in room ${roomName}`);
    }
  }
};


export default webSocketController;