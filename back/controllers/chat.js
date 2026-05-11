import { Room, Message } from '../models/db.js';
import { Op } from 'sequelize';
const timers = {};
import webSocketController from './webSocketController.js';


const chatCtrl = {
hostSendsMessage: async (req, res) => {
    const { hostToken, roomName, message } = req.body;
    if (!hostToken || !roomName || !message) {
        return res.status(400).json({ error: 'Missing hostToken, roomName, or message' });
    }
    const room = await Room.findOne({ where: { roomName, hostToken } });
    if (!room) {
        return res.status(403).json({ error: 'Invalid room or hostToken' });
    }
    const myPending = await Message.count({ 
        where: { roomName, sender: 'host' } 
    });
    if (myPending >= 6) {
        return res.status(429).json({ 
            error: 'Your partner has 6 pending messages: please wait a moment' 
        });
    }
    const order = myPending;
    await Message.create({ 
        roomName, 
        sender: 'host', 
        message, 
        order 
    });
try {
      webSocketController.broadcastMessage(
        roomName, 
        { message, order, sender: 'host' }, 
        'host'   // send to the joiner
      );
      await Message.destroy({
        where: { roomName, order, sender: "host" }
      });
    } catch (err) {
      console.error("WebSocket error (host):", err);
      return res.status(500).json({ 
        error: "Message saved but failed to deliver to joiner via WS" 
      });
    }
    res.json({ success: true });
  },

joinerSendsMessage: async (req, res) => {
    const { joinerToken, roomName, message } = req.body;
    if (!joinerToken || !roomName || !message) {
        return res.status(400).json({ error: 'Missing joinerToken, roomName, or message' });
    }
    const room = await Room.findOne({ where: { roomName, joinerToken } });
    if (!room) {
        const targetRoom = await Room.findOne({ where: { roomName } });
        if (targetRoom) {
            const failedAuthAttemps = targetRoom.failedAuth || 0;
            if (failedAuthAttemps >= 3) {
                await Message.destroy({ where: { roomName } });
                await targetRoom.destroy();
                return res.status(403).json({ error: 'The room was destroyed because 3 failed attempts were detected' });
            }
            await targetRoom.update({ failedAuth: failedAuthAttemps + 1 });
        }
        return res.status(403).json({ error: 'Invalid room or joinerToken' });
    }
    const myPending = await Message.count({ 
        where: { roomName, sender: 'joiner' } 
    });
    if (myPending >= 6) {
        return res.status(429).json({ 
            error: 'Your partner has 6 pending messages: please wait a moment' 
        });
    }
    const order = myPending;
    await Message.create({ 
        roomName, 
        sender: 'joiner', 
        message, 
        order 
    });

     const sent = webSocketController.broadcastMessage(
       roomName,
       { message, order, sender: 'joiner' },
       'joiner'
     );

     if (!sent) {
       return res.status(500).json({
         error: "Message saved but failed to deliver to host via WS"
       });
     }

     await Message.destroy({
       where: { roomName, order, sender: "joiner" }
     });

     res.json({ success: true });
  },


 

  deleteRoom: async (req, res) => {
    const { token, roomName } = req.body;
    if (!token || !roomName)
      return res.status(400).json({ error: 'Missing token or roomName' });
    const room = await Room.findOne({
      where: {
        roomName,
        [Op.or]: { hostToken: token, joinerToken: token }
      }
    });
    if (!room)
      return res.status(403).json({ error: 'Invalid room or token' });
    if (timers[roomName]) {
      clearTimeout(timers[roomName]);
      delete timers[roomName];
    }
    await Message.destroy({ where: { roomName } });
    await room.destroy();
    res.status(200).json({ success: true });
  },
}

export default chatCtrl;