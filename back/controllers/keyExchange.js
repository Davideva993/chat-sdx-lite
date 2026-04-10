import { v4 as uuidv4 } from 'uuid';
import { Room } from '../models/db.js';
const keyExchangeCtrl = {
  /*-----NAME-------------------------------------------INPUT------------------------------------OUTPUT--------
  STEP 1: hostRegistersRoom()                         ------                                   roomName, hostToken
  STEP 2: joinerFindsRoom()                           roomName                                 joinerToken 
  STEP 3: hostAsksForJoiner()                         roomName, hostToken                      ------
  STEP 4: hostSendsEncryptedInitKeyAndNonce()         roomName, hostToken en. initKey, nonce   ------
  STEP 5: joinerAsksForEncryptedInitKeyAndNonce()     roomName, joinerToken                    en. initKey
  STEP 6: joinerSendsEncryptedDefKey()                roomName, joinerToken, en. defKey        ------
  STEP 7: hostAsksForEncryptedDefKey()                roomName, hostToken                      en. defKey
  STEP 8: hostSendsEncryptedSecret()                  roomName, hostToken, en. secret          -------
  STEP 9: joinerAsksForEncryptedSecret()              roomName, joinerToken                    en. secret
  -------------------------------------------CHAT STARTS----------------------------------------------------
  */
  // Step 1 (Host): Register room with room name. Gets the hostToken 
  hostRegistersRoom: async (req, res) => {
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789'; // valid characters for roomName
    let roomName;
    let existingRoom;
    do {
      roomName = '';
      for (let i = 0; i < 5; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        roomName += characters[randomIndex];
      }
      existingRoom = await Room.findOne({ where: { roomName } });
    } while (existingRoom);
    try {
      const hostToken = uuidv4();
      await Room.create({
        roomName,
        hostToken,
      });
      return res.status(200).json({ hostToken, roomName });
    } catch (error) {
      return res.status(500).json({ error: 'Server error' });
    }
  },


  // Step 2 (Joiner): Find the room (roomName) and get the joinerToken
  joinerFindsRoom: async (req, res) => {
    const { roomName } = req.body;
    if (!roomName) {
      return res.status(400).json({ error: 'Missing roomName' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.joinerToken) {
        if (room && room.joinerToken) {
          await Room.destroy({ where: { roomName } }); //potentially compromise attempt detected on the largest time window: the room is destroyed
        }
        return res.status(404).json({ error: 'Room not available', restartFront: true });
      }
      const joinerToken = uuidv4();
      await room.update({ joinerToken });
      setTimeout(() => {
        Room.update(
          { nonce: null, encryptedInitKey: null, encryptedDefKey: null, encryptedSecret: null },
          { where: { roomName } }
        ).catch(() => { })
      }, 12_000)
      res.status(200).json({
        joinerToken,
      });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },



  // Step 3 (Host): Check if joiner has joined
  hostAsksForJoiner: async (req, res) => {
    const { roomName, hostToken } = req.body;
    if (!roomName || !hostToken) {
      return res.status(400).json({ error: 'Missing roomName or hostToken' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.hostToken !== hostToken || room.ongoingChat) {
        if (room && room.hostToken !== hostToken) {
          await room.destroy();
        }
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      else if (!room.joinerToken) {
        return res.status(404).json({ message: 'Joiner is not here, try again' });
      }
      res.status(200).json({ message: "Joiner is here" });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },



  // Step 4 (Host): Send initKey encrypted by tempKey 
  hostSendsEncryptedInitKeyAndNonce: async (req, res) => {
    const { roomName, hostToken, encryptedInitKey, nonce } = req.body;
    if (!roomName || !hostToken || !encryptedInitKey || !nonce) {
      return res.status(400).json({ error: 'Missing roomName, hostToken, nonce or encryptedInitKey' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.ongoingChat) {
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (room && room.hostToken !== hostToken) {
        await room.destroy();
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      await room.update({ encryptedInitKey, nonce });
      res.status(200).json({ success: true });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },



  // Step 5 (Joiner): Ask for initKey encrypted by tempKey 
  joinerAsksForEncryptedInitKeyAndNonce: async (req, res) => {
    const { roomName, joinerToken } = req.body;
    if (!roomName || !joinerToken) {
      return res.status(400).json({ error: 'Missing roomName or joinerToken' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.ongoingChat) {
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (room && room.joinerToken !== joinerToken) {
        await room.destroy();
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (!room.encryptedInitKey) {
        return res.status(404).json({ message: 'encryptedInitKey not found' });
      }
      res.status(200).json({ encryptedInitKey: room.encryptedInitKey, nonce: room.nonce });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },



  // Step 6 (Joiner): Send defKey encrypted by initKey
  joinerSendsEncryptedDefKey: async (req, res) => {
    const { roomName, joinerToken, encryptedDefKey } = req.body;
    if (!roomName || !joinerToken || !encryptedDefKey) {
      return res.status(400).json({ error: 'Missing roomName, joinerToken, or encryptedDefKey' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.ongoingChat) {
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (room && room.joinerToken !== joinerToken) {
        await room.destroy();
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      await room.update({ encryptedDefKey });
      res.status(200).json({ success: true });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },



  // Step 7 (Host): Ask for the defKey encrypted by initKey
  hostAsksForEncryptedDefKey: async (req, res) => {
    const { roomName, hostToken } = req.body;
    if (!roomName || !hostToken) {
      return res.status(400).json({ error: 'Missing roomName or hostToken' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.ongoingChat) {
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (room && room.hostToken !== hostToken) {
        await room.destroy();
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (!room.encryptedDefKey) {
        return res.status(404).json({ message: 'encryptedDefKey not found' });
      }
      res.status(200).json({ encryptedDefKey: room.encryptedDefKey || null });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },



  //Step 8 (host): Send a secret (secretCode2) encrypted by defKey
  hostSendsEncryptedSecret: async (req, res) => {
    const { roomName, hostToken, encryptedSecret } = req.body;
    if (!roomName || !hostToken || !encryptedSecret) {
      return res.status(400).json({ error: 'Missing roomName, hostToken, or encryptedSecret' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.ongoingChat) {
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (room && room.hostToken !== hostToken) {
        await room.destroy();
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      await room.update({ encryptedSecret });
      res.status(200).json({ success: true });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },



  //Step 9 (joiner): Ask for the secret (secretCode2) encrypted by defKey
  joinerAsksForEncryptedSecret: async (req, res) => {
    const { roomName, joinerToken } = req.body;
    if (!roomName || !joinerToken) {
      return res.status(400).json({ error: 'Missing roomName or joinerToken' });
    }
    try {
      const room = await Room.findOne({ where: { roomName } });
      if (!room || room.ongoingChat) {
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (room && room.joinerToken !== joinerToken) {
        await room.destroy();
        return res.status(403).json({ error: 'Invalid request', restartFront: true });
      }
      if (!room.encryptedSecret) {
        return res.status(404).json({ message: 'encryptedSecret not found' });
      }
      await room.update({ ongoingChat: true });
      res.status(200).json({ encryptedSecret: room.encryptedSecret });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  },
}
export default keyExchangeCtrl;

