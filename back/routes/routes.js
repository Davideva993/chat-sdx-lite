// routes/routes.js (ESM mode)
import express from "express";
import keyExchangeCtrl from "../controllers/keyExchange.js";
import chatCtrl from "../controllers/chat.js";

const router = express.Router();

// KeyExchange routes 
router.post('/hostRegistersRoom', keyExchangeCtrl.hostRegistersRoom); 
router.post('/joinerFindsRoom', keyExchangeCtrl.joinerFindsRoom); 
router.post('/hostAsksForJoiner', keyExchangeCtrl.hostAsksForJoiner); 
router.post('/hostSendsEncryptedInitKeyAndNonce', keyExchangeCtrl.hostSendsEncryptedInitKeyAndNonce);
router.post('/joinerAsksForEncryptedInitKeyAndNonce', keyExchangeCtrl.joinerAsksForEncryptedInitKeyAndNonce);
router.post('/hostAsksForEncryptedDefKey', keyExchangeCtrl.hostAsksForEncryptedDefKey);
router.post('/joinerSendsEncryptedDefKey', keyExchangeCtrl.joinerSendsEncryptedDefKey);
router.post('/hostSendsEncryptedSecret', keyExchangeCtrl.hostSendsEncryptedSecret);
router.post('/joinerAsksForEncryptedSecret', keyExchangeCtrl.joinerAsksForEncryptedSecret);

// Chat routes 
router.post('/hostSendsMessage', chatCtrl.hostSendsMessage); 
router.post('/joinerSendsMessage', chatCtrl.joinerSendsMessage); 
router.post('/deleteRoom', chatCtrl.deleteRoom);


router.get('/getTurnCredentials', turnCtrl.getTurnCredentials);



export default router;