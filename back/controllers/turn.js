import crypto from 'crypto';
import { Room } from '../models/db.js';
import { Op } from 'sequelize';
import dotenv from 'dotenv';
dotenv.config();
const TURN_SECRET = Buffer.from(process.env.TURN_REST_SECRET, 'utf8');
const TURN_EXPIRY = parseInt(process.env.TURN_CRED_EXPIRY_SECONDS) || 3600;
const turnCtrl = {
  getTurnCredentials: async (req, res) => {

    //console.log("ENV CHECK - TURN_REST_SECRET exists:", !!process.env.TURN_REST_SECRET);
    //console.log("ENV CHECK - TURN_SERVER_URL:", process.env.TURN_SERVER_URL);

    const { roomName, token } = req.query;
    if (!roomName || !token) return res.status(400).json({ error: 'Missing roomName or token' });
    const room = await Room.findOne({
      where: { roomName, [Op.or]: [{ hostToken: token }, { joinerToken: token }] }
    });
    if (!room) return res.status(403).json({ error: 'Invalid room or token' });
    const expiry = Math.floor(Date.now() / 1000) + TURN_EXPIRY;
    const username = expiry.toString();
    const hmac = crypto.createHmac('sha1', TURN_SECRET);
    hmac.update(username);
    const password = hmac.digest('base64');
    res.status(200).json({
      iceServers: [
        { urls: process.env.TURN_SERVER_STUN_URL },
        { urls: process.env.TURN_SERVER_URL, username, credential: password, credentialType: 'password' }
      ]
    });
  }
};
export default turnCtrl;