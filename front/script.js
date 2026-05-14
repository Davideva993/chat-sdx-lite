
/*
-The steps:
1)The host generates a nonce, the tempKey (using secretCode1 and Argon), the initKey (public RSA-OAEP) then he registers a room and receives the hostToken and the roomName.
2)The host asks each 1,5s if the other user (joiner) joined the room.
3)The joiner generates the defKey (AES), joins the room (with roomName) and receives the joinerToken.
4)The host, knowing the joiner is present, generates a self-destruct timer and sends the initKey encrypted by the tempKey and the nonce to the server.
5)The joiner asks for the nonce and encrypted initKey. Then he generates the tempKey (secretCode1, nonce and Argon) and uses it to decrypt the initKey.
6)The joiner starts a self-destruct timer, encrypts the defKey + random nonce using the decrypted initKey and sends it to the server. The first currentKey is the defKey derived with this nonce and the secretCode2.
7)The host polls every 1.5 s for the defKey encrypted by the initKey. When it arrives it is decrypted, the trailing 16-byte nonce is used with the secretCode2 to derivate the first currentKey, and the clean defKey is imported. The self-destruct timer is cleared.
8)The host Encrypts the hash of secretCode2 using the defKey and sends it to the server.
9)The joiner ask for the encrypted hash of SecretCode2, decrypts it, compares it. If matches, the processus is validated and the joiner timer cleared.
----the chat starts---
-The first message is encrypted with defKey derived with the nonce (step 6 or 7) and the secretCode2. Then:
10)The sender encrypts a message (3 digits indicating the message length + the realMessage + padding up to 420 characters + extra random padding of 0–79 characters, e.g., 006Hello!awefTRe47...) or a file (4-char file ext + 7-digit length + file bytes + padding up to 1 MiB) + a 32 byte fresh AES (next AES key) + a 16 byte nonce (derivationNonce) using currentDefKey and sends it. Then updates cumulativeNonce (first message: defKey as currentKey and the nonce sent with defKey as derivationNonce and secretCode2; later: SHA-256(old||new)[0:15]) and derives the next currentDefKey = AES derived with secretCode2 + cumulativeNonce.
11)The receiver decrypts using currentDefKey, gets the AES and derivationNonce, updates cumulativeNonce exactly the same way (first message: defKey as currentKey and the nonce sent with defKey as derivationNonce and secretCode2; later: SHA-256(old||new)[0:15]), then derives the next currentDefKey = AES derived with secretCode2 + cumulativeNonce.  
            
*/
function app() {
    'use strict'
    //console.log("Argon2:", typeof argon2 !== "undefined" ? "ok" : "error");
    const dynamicElements = document.getElementsByClassName("dynamic")
    const c18 = "#1b2330"
    const c9 = "#cfe7ff"
    const c25 = "#FF0000"
    const c26 = "#369900"
    const c8 = "#4db8ff";
    let userName
    let tempKey
    let keyPair
    let roomName
    let joinerToken
    let hostToken
    let secretCode1
    let secretCode2
    let initKey
    let nonce
    let defKey
    let stopStepsAnimation = false
    let countdownInterval = null
    let countDownSeconds = 9
    let initKeyCrypto
    let cumulativeNonce = null
    let sendOk = false
    let chatMessages = [];

    updateDynamicElements("landingPage")
    hostBtnStart.addEventListener("click", () => updateDynamicElements("hostPage"))
    joinBtnStart.addEventListener("click", () => updateDynamicElements("joinPage"))
    backButton.addEventListener("click", () => updateDynamicElements("landingPage"))
    hostBtnEnd.addEventListener("click", hostSetupAndRegisterARoom)
    joinBtnEnd.addEventListener("click", joinerSetupAndFindsRoom)
    reloadButton.addEventListener("click", () => { location.reload() })

    // IndexedDB helpers
    function openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open("ChatSDX", 1);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains("conversations")) {
                    db.createObjectStore("conversations", { keyPath: "roomName" });
                }
            };
            request.onsuccess = (e) => resolve(e.target.result);
            request.onerror = (e) => reject(e.target.error);
        });
    }

    async function dbGetAll() {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("conversations", "readonly");
            const store = tx.objectStore("conversations");
            const request = store.getAll();
            request.onsuccess = () => {
                const result = {};
                request.result.forEach(item => { result[item.roomName] = item.data; });
                resolve(result);
            };
            request.onerror = () => reject(request.error);
        });
    }

    async function dbPut(roomName, data) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("conversations", "readwrite");
            const store = tx.objectStore("conversations");
            store.put({ roomName, data });
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async function dbDelete(roomName) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("conversations", "readwrite");
            const store = tx.objectStore("conversations");
            store.delete(roomName);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // Save-load chat part: 
    //  Save: user enters a password generates an AES (argon2) to encrypt the message and sensitive conversation data and store in IndexedDB. RoomName is encrypted ans stored too. AES and password aren't stored.
    //  Load: user enters the password and to generate the AES exactly as in the "save part". Then try to encrypt the roomName and compare with the encrypted roomName. If matches, password (and AES) are right so chipertext will be decrypted.   
    async function saveChat() {
        const pwd = prompt("Enter a password... and don't forget it");
        if (!pwd || pwd.length < 4) {
            alert("Password too short. Minimum 4 characters.");
            return false;
        }
        try {
            const salt = crypto.getRandomValues(new Uint8Array(32));
            const passwordBuffer = new TextEncoder().encode(pwd);
            const argon2Params = {
                pass: passwordBuffer,
                salt: salt,
                time: 3,
                mem: 32768,
                hashLen: 32,
                parallelism: 1,
                type: argon2.Argon2id,
            };
            const hash = await argon2.hash(argon2Params);
            let keyBytes;
            if (hash.hash instanceof Uint8Array) {
                keyBytes = hash.hash;
            } else if (hash.hash instanceof ArrayBuffer) {
                keyBytes = new Uint8Array(hash.hash);
            } else if (typeof hash.hash === 'string') {
                keyBytes = hexToUint8Array(hash.hash);
            } else {
                throw new Error("Unsupported Argon2 hash format");
            }
            if (keyBytes.length !== 16 && keyBytes.length !== 32) {
                console.error("Derived key length invalid:", keyBytes.length);
                return false;
            }
            const masterKey = await crypto.subtle.importKey(
                'raw',
                keyBytes.buffer,
                { name: 'AES-GCM' },
                true,
                ['encrypt', 'decrypt']
            );
            const exported = await crypto.subtle.exportKey('raw', currentDefKey);
            const currentDefKeyRaw = Array.from(new Uint8Array(exported));
            let sessionData
            if (userName === "host") {
                sessionData = {
                    secretCode2: secretCode2,
                    cumulativeNonce: Array.from(cumulativeNonce),
                    currentDefKeyRaw: currentDefKeyRaw,
                    hostToken: hostToken,
                    roomName: roomName,
                    messages: chatMessages,
                };
            } else if (userName === "joiner") {
                sessionData = {
                    secretCode2: secretCode2,
                    cumulativeNonce: Array.from(cumulativeNonce),
                    currentDefKeyRaw: currentDefKeyRaw,
                    joinerToken: joinerToken,
                    roomName: roomName,
                    messages: chatMessages,
                };
            }
            const dataString = JSON.stringify(sessionData);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                masterKey,
                new TextEncoder().encode(dataString)
            );
            const encryptedRoomName = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                masterKey,
                new TextEncoder().encode(roomName)
            );

            const conversationEntry = {
                [roomName]: {
                    encryptedRoomName: Array.from(new Uint8Array(encryptedRoomName)), // when restore, user will try to recreate the same key and use it to encrypt the roomName and see if matches with this one => if matches, password is right => can decrypt the chat
                    version: 1,
                    salt: Array.from(salt),
                    iv: Array.from(iv),
                    ciphertext: Array.from(new Uint8Array(encryptedBuffer))
                }
            };
            await dbPut(roomName, conversationEntry[roomName]);
            await displaySavedRooms()
            alert(`✅ Conversation "${roomName}" saved successfully!`);
            //console.log(`Saved conversation: ${roomName}`);
            return true;
        } catch (error) {
            console.error("Save error:", error);
            alert("Failed to save the conversation. Check console.");
            return false;
        }
    }


    async function displaySavedRooms() {
        const ul = document.getElementById("savedRooms")
        ul.innerHTML = ""
        const myConversations = await dbGetAll()
        if (Object.keys(myConversations).length == 0) {
            ul.innerHTML = "<li>No saved conversations</li>"
        }
        else {
            Object.keys(myConversations).forEach(room => {
                const li = document.createElement("li")
                li.textContent = room
                li.style.cursor = "pointer"
                li.style.padding = "10px"
                li.style.margin = "6px 0"
                li.style.backgroundColor = c18
                li.style.borderRadius = "6px"
                li.style.listStyle = "none"
                li.addEventListener("mouseenter", () => {
                    li.style.boxShadow = "0 0 12px " + c8
                })
                li.addEventListener("mouseleave", () => {
                    li.style.boxShadow = "none"
                })
                li.addEventListener("click", () => {
                    restoreSavedRoom(room)
                })
                ul.appendChild(li)
            })
        }
    }

    async function restoreSavedRoom(room) {
        const myConversations = await dbGetAll()
        const saved = myConversations[room]
        if (!saved) {
            alert("Room not found")
            return
        }
        await loadChat(room)
    }

    async function loadChat(requestedRoomName) {
        if (!requestedRoomName || requestedRoomName.trim() === "") {
            alert("Room name is required.");
            return false;
        }
        const myConversations = await dbGetAll();
        const savedChat = myConversations[requestedRoomName];
        if (!savedChat) {
            //console.log(savedChat)
            alert(`No saved conversation found for room: ${requestedRoomName}`);
            return false;
        }
        const pwd = prompt(`Enter the password to recover conversation "${requestedRoomName}"`);
        if (!pwd) {
            return false;
        }
        try {
            const salt = new Uint8Array(savedChat.salt);
            const iv = new Uint8Array(savedChat.iv);
            const ciphertext = new Uint8Array(savedChat.ciphertext);
            const passwordBuffer = new TextEncoder().encode(pwd);
            const argon2Params = {
                pass: passwordBuffer,
                salt: salt,
                time: 3,
                mem: 32768,
                hashLen: 32,
                parallelism: 1,
                type: argon2.Argon2id,
            };
            const hash = await argon2.hash(argon2Params);
            let keyBytes;
            if (hash.hash instanceof Uint8Array) {
                keyBytes = hash.hash;
            } else if (hash.hash instanceof ArrayBuffer) {
                keyBytes = new Uint8Array(hash.hash);
            } else if (typeof hash.hash === 'string') {
                keyBytes = hexToUint8Array(hash.hash);
            } else {
                throw new Error("Unsupported Argon2 hash format");
            }
            if (keyBytes.length !== 16 && keyBytes.length !== 32) {
                console.error("Derived key length invalid:", keyBytes.length);
                alert("Errore interno: chiave derivata non valida.");
                return false;
            }
            //console.log("derived master key length:", keyBytes.length);
            const masterKey = await crypto.subtle.importKey(
                'raw',
                keyBytes.buffer,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );
            const roomNameBuffer = new TextEncoder().encode(requestedRoomName);
            const encryptedRoomNameTest = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                masterKey,
                roomNameBuffer
            );
            const testArray = new Uint8Array(encryptedRoomNameTest);
            const savedArray = new Uint8Array(savedChat.encryptedRoomName);
            //console.log("Test encrypted length:", testArray.length);
            //console.log("Saved encrypted length:", savedArray.length);
            if (testArray.length !== savedArray.length ||
                !testArray.every((byte, i) => byte === savedArray[i])) {
                //console.log("❌ Password mismatch - lengths or bytes differ");
                alert("Wrong password");
                return false;
            }
            //console.log("✅ Password verified successfully");
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                masterKey,
                ciphertext
            );
            const sessionData = JSON.parse(new TextDecoder().decode(decryptedBuffer));
            roomName = sessionData.roomName
            //console.log(sessionData)
            //console.log(roomName)
            if (sessionData.hostToken) {
                hostToken = sessionData.hostToken
                userName = "host"
            }
            else if (sessionData.joinerToken) {
                joinerToken = sessionData.joinerToken
                //console.log(joinerToken, roomName)
                userName = "joiner"
            }
            secretCode2 = sessionData.secretCode2;
            cumulativeNonce = new Uint8Array(sessionData.cumulativeNonce);
            const curKeyBytes2 = new Uint8Array(sessionData.currentDefKeyRaw);
            //console.log("restored currentDefKey length:", curKeyBytes2.length);
            if (curKeyBytes2.length !== 16 && curKeyBytes2.length !== 32) {
                throw new Error("Invalid currentDefKey length: " + curKeyBytes2.length);
            }
            currentDefKey = await crypto.subtle.importKey(
                'raw',
                curKeyBytes2,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );
            const ul = document.getElementById("ulChat");
            ul.innerHTML = "";
            chatMessages = []
            sessionData.messages.forEach(msg => {
                //console.log(sessionData)
                if (msg.type === "file") {
                    const bytes = new Uint8Array(msg.bytes);
                    addFileMessage(bytes, msg.ext, msg.user);
                } else {
                    addTextMessage(msg.text, msg.user);
                }
            });
            alert(`✅ Conversation "${requestedRoomName}" loaded and decrypted successfully !`);
            //console.log(`Loaded encrypted conversation: ${requestedRoomName}`);
            updateDynamicElements("chatPage");
            if (chatWS) {
                try { chatWS.close(); } catch (e) { }
            }
            //console.log("WS OPENING WITH:", roomName, hostToken, joinerToken);
            connectChatWebSocket();
            document.getElementById("roomNameH2").textContent = roomName;
            return true;
        } catch (error) {
            console.error("Load error:", error);
            return false;
        }
    }

    function hexToUint8Array(hex) {
        if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
        const arr = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            arr[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return arr;
    }



    //--------------------------------------Design functions
    function updateDynamicElements(classToShow) {
        for (let i = 0; i < dynamicElements.length; i++) {
            if (!dynamicElements[i].classList.contains(classToShow)) {
                dynamicElements[i].style.display = "none";
            } else {
                dynamicElements[i].style.display = "";
            }
        }
        if (classToShow === "landingPage") {
            displaySavedRooms()
        }
        const label = document.querySelector('label[for="roomNameInput"]')
        if (classToShow == "chatPage") {
            document.getElementById("centralSection").style.height = "60vh"
        }
        else if (classToShow == "hostPage") {
            document.getElementById("roomNameInput").readOnly = true;
            document.getElementById("roomNameInput").style.background = "#1a1f27";
            document.getElementById("roomNameInput").style.outline = "none";
            document.getElementById("roomNameInput").value = "";
            label.textContent = "Room name (will be auto-filled)"
        }
        else if (classToShow == "joinPage") {
            document.getElementById("roomNameInput").readOnly = false;
            document.getElementById("roomNameInput").style.background = "#141a22; ";
            document.getElementById("roomNameInput").style.outline = "initial";
            document.getElementById("roomNameInput").style.color = c9;


            label.textContent = "Room name (please ask the other user)"
        }
    }

    function showBorderEffect(user, containerId) {
        let userClassName
        if (user == "host") {
            userClassName = ".hostPage.drawingSec"
        }
        else if (user == "joiner") {
            userClassName = ".joinPage.drawingSec"
        }
        let containerEffectClassName = containerId + "BorderEffect"
        let targetClass = userClassName + " ." + containerId //identify the element (img container)
        document.querySelector(targetClass).classList.add(containerEffectClassName)
    }

    function stepsAnimation(nextStep, user, result) {
        if (result == "completed" && stopStepsAnimation == false) {
            if (user == "host") {
                if (nextStep == "tempKey") {
                    document.getElementById("tempKeyHostLegend").textContent = "Working on it..."
                }
                if (nextStep == "initKey") {
                    document.querySelectorAll(".showcaseSection").forEach(el => {
                        el.style.display = "none";
                    })
                    document.getElementById("initKeyHostLegend").textContent = "Working on it..."
                    document.getElementById("tempKeyHostLegend").textContent = "TempKey, an AES‑GCM key, was successfully generated locally from the secrets using Argon2."
                    document.getElementById("tempKeyHostImg").classList.add("stepCompleted")
                }
                if (nextStep == "defKey") {
                    document.getElementById("defKeyHostLegend").textContent = "Working on it..."
                    document.getElementById("initKeyHostLegend").textContent = "initKey, your public RSA-OAEP, was encrypted by tempKey and successfully sent to the server."
                    document.getElementById("initKeyHostImg").classList.add("stepCompleted")
                }
                if (nextStep == "validated") {
                    document.getElementById("lockStatusHostLegend").textContent = "Working on it..."
                    document.getElementById("defKeyHostLegend").textContent = "defKey, an AES-GCM encrypted by initKey, was received and decrypted."
                    document.getElementById("defKeyHostImg").classList.add("stepCompleted")
                }
                if (nextStep == "chat") {
                    document.getElementById("lockStatusHostLegend").textContent = "The hash of the secret2 was successfully encrypted by defKey and sent to the server. Waiting for your partner’s validation."
                    document.getElementById("lockStatusHostImg").src = "./assets/locked.webp"
                }
            }
            else if (user == "joiner") {
                if (nextStep == "tempKey") {
                    document.getElementById("tempKeyJoinerLegend").textContent = "Working on it..."
                }
                if (nextStep == "initKey") {
                    document.querySelectorAll(".showcaseSection").forEach(el => {
                        el.style.display = "none";
                    })
                    document.getElementById("initKeyJoinerLegend").textContent = "Working on it..."
                    document.getElementById("tempKeyJoinerLegend").textContent = "TempKey, an AES‑GCM key, was successfully generated locally from the secrets using Argon2."
                    document.getElementById("tempKeyJoinerImg").classList.add("stepCompleted")
                }
                if (nextStep == "defKey") {
                    document.getElementById("defKeyJoinerLegend").textContent = "Working on it..."
                    document.getElementById("initKeyJoinerLegend").textContent = "initKey, the host public RSA-OAEP key encrypted by tempKey, was received and decrypted."
                    document.getElementById("initKeyJoinerImg").classList.add("stepCompleted")
                }
                if (nextStep == "validated") {
                    document.getElementById("lockStatusJoinerLegend").textContent = "Working on it..."
                    document.getElementById("defKeyJoinerLegend").textContent = "defKey, an AES-GCM key, was encrypted by initKey and sent to the server."
                    document.getElementById("defKeyJoinerImg").classList.add("stepCompleted")
                }
                if (nextStep == "chat") {
                    document.getElementById("lockStatusJoinerLegend").textContent = "The hash of the secret2 encrypted by defKey received, decrypted and successfully validated. The chat can begin."
                    document.getElementById("lockStatusJoinerImg").src = "./assets/locked.webp"
                }
            }
        }
        else if (result == "failed") {
            stopStepsAnimation = true
            if (user == "host") {
                if (nextStep == "tempKey") {
                    document.getElementById("tempKeyJoinerLegend").textContent = "tempKey couldn't be generated."
                    document.getElementById("tempKeyJoinerImg").classList.add("stepFailed")
                }
                if (nextStep == "initKey") {
                    document.getElementById("initKeyHostLegend").textContent = "initKey couldn't be generated, encrypted or sent."
                    document.getElementById("initKeyHostImg").classList.add("stepFailed")
                }
                if (nextStep == "defKey") {
                    document.getElementById("defKeyHostLegend").textContent = "defKey couldn't be received or decrypted."
                    document.getElementById("defKeyHostImg").classList.add("stepFailed")
                }
                if (nextStep == "validated") {
                    document.getElementById("lockStatusHostLegend").textContent = "Secret couldn't be encrypted or sent."
                    document.getElementById("lockStatusJoinerImg").classList.add("stepFailed")
                }

            }
            else if (user == "joiner") {
                if (nextStep == "tempKey") {
                    document.getElementById("tempKeyJoinerLegend").textContent = "tempKey couldn't be generated."
                    document.getElementById("tempKeyJoinerImg").classList.add("stepFailed")
                }
                if (nextStep == "initKey") {
                    document.getElementById("initKeyJoinerLegend").textContent = "initKey couldn't be received or decrypted. Is the secretCode1 right?"
                    document.getElementById("initKeyJoinerImg").classList.add("stepFailed")
                }
                if (nextStep == "defKey") {
                    document.getElementById("defKeyJoinerLegend").textContent = "defKey couldn't be generated, encrypted or sent."
                    document.getElementById("defKeyJoinerImg").classList.add("stepFailed")
                }
                if (nextStep == "validated") {
                    document.getElementById("lockStatusJoinerLegend").textContent = "Secret couldn't be received or decrypted."
                    document.getElementById("lockStatusJoinerImg").classList.add("stepFailed")
                }
                if (nextStep == "chat") {
                    document.getElementById("lockStatusJoinerLegend").textContent = "The host is not verified. He sent a wrong secret code 2."
                    document.getElementById("lockStatusJoinerImg").classList.add("stepFailed")
                }
            }
        }
    }


    //--------------------------------Functional functions (keyExchange)

    function restartFront() {
        alert("The chat cannot start. The room name is wrong, the room was removed for security reasons, or a chat is already active. Please try again and inform your partner.");
        location.reload()
    }

    function timer(user, action) {
        if (action == "start" && countdownInterval || action == "stop" && countdownInterval == null) {
            return
        }
        else {
            if (user == "host" && action == "start") {
                const countdownP = document.getElementById("destroyChatHostP")
                const destroyLegend = document.getElementById("destroyChatHostLegend")
                let destroyLegendMsg = "For security reasons, the deadline to get a defKey (blue) is: "
                destroyLegend.textContent = destroyLegendMsg + countDownSeconds
                countdownInterval = setInterval(() => {
                    countDownSeconds--
                    countdownP.textContent = countDownSeconds
                    destroyLegend.textContent = destroyLegendMsg + countDownSeconds
                    if (countDownSeconds == 0) {
                        clearInterval(countdownInterval);
                        countdownInterval = null;
                        alert("InitKey could be compromised, please host a new room.")
                        deleteRoom()
                        setTimeout(() => {
                            location.reload()
                        }, 1000);
                    }
                }, 1000);
            }
            if (user == "joiner" && action == "start") {
                const countdownP = document.getElementById("destroyChatJoinerP")
                const destroyLegend = document.getElementById("destroyChatJoinerLegend")
                let destroyLegendMsg = "The deadline to get a defKey (blue) is: "
                destroyLegend.textContent = destroyLegendMsg + countDownSeconds
                countdownInterval = setInterval(() => {
                    countDownSeconds--
                    countdownP.textContent = countDownSeconds
                    destroyLegend.textContent = destroyLegendMsg + countDownSeconds
                    if (countDownSeconds == 0) {
                        clearInterval(countdownInterval);
                        countdownInterval = null;
                        alert("Something's off... please join another room.")
                    }
                }, 1000);
            }
            if (action === "stop") {
                let destroyLegend
                let countdownP
                let targetId = "#" + user + "DestroyChatDrawingContainer .destroyChatImgContainer" //identify the element (img container)
                document.querySelector(targetId).classList.add("stepCompleted")
                if (user == "host") {
                    destroyLegend = document.getElementById("destroyChatHostLegend")
                    countdownP = document.getElementById("destroyChatHostP")
                }
                else if (user == "joiner") {
                    destroyLegend = document.getElementById("destroyChatJoinerLegend")
                    countdownP = document.getElementById("destroyChatJoinerP")
                }
                clearInterval(countdownInterval);
                countdownInterval = null;
                destroyLegend.textContent = "Self-destruct deactivated: time check passed."
                countdownP.textContent = ""
            }
        }
    }

    //1)The host generates a nonce, the tempKey (using secretCode1 and Argon), the initKey (public RSA-OAEP) then he registers a room with the roomName and receives the hostToken.
    function hostSetupAndRegisterARoom() {
        secretCode1 = roomSecretCodeInput1.value
        secretCode2 = roomSecretCodeInput2.value
        stepsAnimation("tempKey", "host", "completed")
        hostGeneratesNonce()
        hostGeneratesTempKey()
        hostGeneratesInitKey()
        hostRegistersRoom()

    }

    async function hostGeneratesTempKey() {
        try {
            // Password into buffer (UTF-8)
            const passwordBuffer = new TextEncoder().encode(secretCode1);
            // Argon2 parameters
            const argon2Params = {
                pass: passwordBuffer,           // Uint8Array: UTF-8 encoded password (secret input)
                salt: nonce,                    // Uint8Array: 16+ byte random salt (unique per derivation, prevents rainbow tables)
                time: 3,                        // Integer: iterations (cost factor); 3 = ~0.5–1s in browser (1–5 safe, >5 risks UI freeze)
                mem: 32768,                     // Integer (KiB): memory usage; 32768 KiB = 32 MiB (safe range: 8–64 MiB, avoid >64 MiB)
                hashLen: 32,                    // Integer (bytes): output key length; 32 = 256-bit key for AES-256
                parallelism: 1,                 // Integer: lanes/threads; MUST be 1 in browser (multi-threading unsupported & causes OOM/crash)
                type: argon2.Argon2id,          // Enum: Argon2id = hybrid (GPU + side-channel resistant) – recommended standard
            };
            // Derivate the key using Argon2
            const hash = await argon2.hash(argon2Params);
            // Derivated hash into a CryptoKey per AES-GCM
            const key = await crypto.subtle.importKey(
                'raw',
                hash.hash, // Buffer that contains the derivated key (32 byte)
                { name: 'AES-GCM' },
                false, // Not extraible
                ['encrypt', 'decrypt']
            );
            tempKey = key
        } catch (error) {
            console.error(error);
            stepsAnimation("tempKey", "host", "failed")
            throw error;
        }
    }

    function hostGeneratesNonce() {
        nonce = crypto.getRandomValues(new Uint8Array(16));
    }

    async function hostGeneratesInitKey() {
        try {
            keyPair = await crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP", // Algorithm
                    modulusLength: 4096, // Key length in bits
                    publicExponent: new Uint8Array([1, 0, 1]), // Public exponent (65537)
                    hash: "SHA-256", // Hash algorithm
                },
                false, // Non-extractable (applies to private key)
                ["encrypt", "decrypt"] // Key usages
            );
            initKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
        } catch (error) {
            console.error("initKey generation error:", error);
            stepsAnimation("initKey", "host", "failed")
            return null;
        }
    }

    function hostRegistersRoom() {
        if (roomSecretCodeInput1.value.length < 6 || roomSecretCodeInput2.value.length < 12) {
            alert("Secret code not valid")
            return
        }
        fetch('http://localhost:3006/api/hostRegistersRoom', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        })
            .then(res => {
                if (res.status === 400) {
                    alert("Impossible to create the room");
                    throw new Error("Bad request");
                }
                return res.json();
            })
            .then(data => {
                hostToken = data.hostToken;
                roomName = data.roomName;
                document.getElementById("roomNameInput").value = roomName
                document.getElementById("roomNameH2").textContent = roomName
                userName = "host";
                hostAsksForJoiner();
            })
            .catch(err => console.error(err));
    }



    //2)The host asks each 1,5s if the other user (joiner) joined the room.
    function hostAsksForJoiner() {
        fetch('http://localhost:3006/api/hostAsksForJoiner', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                roomName: roomName,
                hostToken: hostToken
            })
        })
            .then(async response => {
                const data = await response.json()
                if (data.restartFront === true) {
                    restartFront()
                    return
                }
                if (response.status === 404) {
                    setTimeout(() => {
                        hostAsksForJoiner();
                    }, 1500);
                    return;
                }
                if (!response.ok) {
                    return;
                }

                hostEncryptsInitKey();

            })
            .catch(error => console.error('Error:', error));
    }


    //3)The joiner generates the defKey (AES), joins the room (with roomName) and receives the joinerToken.
    function joinerSetupAndFindsRoom() {
        if (roomNameInput.value.trim().length == 0) {
            alert("Missing room name")
            return
        }
        else if (roomSecretCodeInput1.value.trim().length == 0) {
            alert("Missing room SecretCode1")
            return
        }
        else if (roomSecretCodeInput2.value.trim().length == 0) {
            alert("Missing room SecretCode2")
            return
        }
        else {
            roomName = roomNameInput.value
            document.getElementById("roomNameH2").textContent = roomName
            secretCode1 = roomSecretCodeInput1.value
            secretCode2 = roomSecretCodeInput2.value
            stepsAnimation("tempKey", "joiner", "completed")
            joinerGeneratesDefKey()
            joinerFindsRoom()
        }
    }

    async function joinerGeneratesDefKey() {
        try {
            const key = await crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256,
                },
                true, //Extraible
                ['encrypt', 'decrypt']
            );
            defKey = key
        } catch (error) {
            console.error('Cannot generate the key:', error);
            stepsAnimation("defKey", "joiner", "failed")

            throw error;
        }
    }

    function joinerFindsRoom() {
        fetch('http://localhost:3006/api/joinerFindsRoom', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                roomName: roomName
            })
        })
            .then(async response => {
                const data = await response.json();
                if (data.restartFront === true) {
                    restartFront()
                    return
                }
                if (response.status === 404) {
                    alert("Room not found");
                    throw new Error("Room not found");
                }
                return data
            })
            .then(data => {
                if (!data) return
                joinerToken = data.joinerToken;
                userName = "joiner";
                joinerAsksForEncryptedInitKeyAndNonce();
            })
            .catch(error => console.error(error)
            );
    }

    function base64NonceIntoUint8Array(base64Nonce) {
        // Step 1: Decode base64 to a binary string
        const binaryString = atob(base64Nonce);
        // Step 2: Convert binary string to ArrayBuffer
        const buffer = new ArrayBuffer(binaryString.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binaryString.length; i++) {
            view[i] = binaryString.charCodeAt(i);
        }
        // Step 3: save the Uint8Array nonce
        nonce = view
    }

    async function joinerGeneratesTempKey() {
        try {
            // Password into buffer (UTF-8)
            const passwordBuffer = new TextEncoder().encode(secretCode1);
            // Argon2 parameters
            const argon2Params = {
                pass: passwordBuffer,           // Uint8Array: UTF-8 encoded password (secret input)
                salt: nonce,                    // Uint8Array: 16+ byte random salt (unique per derivation, prevents rainbow tables)
                time: 3,                        // Integer: iterations (cost factor); 3 = ~0.5–1s in browser (1–5 safe, >5 risks UI freeze)
                mem: 32768,                     // Integer (KiB): memory usage; 32768 KiB = 32 MiB (safe range: 8–64 MiB, avoid >64 MiB)
                hashLen: 32,                    // Integer (bytes): output key length; 32 = 256-bit key for AES-256
                parallelism: 1,                 // Integer: lanes/threads; MUST be 1 in browser (multi-threading unsupported & causes OOM/crash)
                type: argon2.Argon2id,          // Enum: Argon2id = hybrid (GPU + side-channel resistant) – recommended standard
            };
            // Derivate the key using Argon2
            const hash = await argon2.hash(argon2Params);
            // Derivated hash into a CryptoKey per AES-GCM
            const key = await crypto.subtle.importKey(
                'raw',
                hash.hash, // Buffer that contains the derivated key (32 byte)
                { name: 'AES-GCM' },
                false, // Not extraible
                ['encrypt', 'decrypt']
            );
            tempKey = key
        } catch (error) {
            stepsAnimation("tempKey", "joiner", "failed")
            console.error(error);
            throw error;
        }
    }



    //4)The host, knowing the joiner is present, generates a self-destruct timer and sends the initKey encrypted by the tempKey and the nonce to the server.
    async function hostEncryptsInitKey() {
        try {
            stepsAnimation("initKey", "host", "completed")
            const initKeyJSON = JSON.stringify(initKey);
            const encoder = new TextEncoder();
            const data = encoder.encode(initKeyJSON);
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce },
                tempKey,
                data
            );
            const result = new Uint8Array(nonce.byteLength + encrypted.byteLength);
            result.set(nonce, 0);
            result.set(new Uint8Array(encrypted), nonce.byteLength);
            const base64 = btoa(String.fromCharCode(...result));
            showBorderEffect("host", "initKeyImgContainer")

            hostSendsEncryptedInitKeyAndNonce(base64);
        } catch (error) {
            console.error("initKey crypto error:", error);
            stepsAnimation("initKey", "host", "failed")
        }
    }
    async function hostSendsEncryptedInitKeyAndNonce(encryptedInitKey) {
        timer("host", "start")
        fetch('http://localhost:3006/api/hostSendsEncryptedInitKeyAndNonce', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                roomName: roomName,
                hostToken: hostToken,
                encryptedInitKey: encryptedInitKey,
                nonce: btoa(String.fromCharCode(...nonce))
            })
        })
            .then(response => response.json())
            .then(data => {
                stepsAnimation("defKey", "host", "completed")
                hostAsksForEncryptedDefKey()
            })
            .catch(error => {
                console.error('Error:', error)
                stepsAnimation("initKey", "host", "failed")
            })
    }


    //5)The joiner asks for the nonce and encrypted initKey. Then he generates the tempKey (secretCode1, nonce and Argon) and uses it to decrypt the initKey
    function joinerAsksForEncryptedInitKeyAndNonce() {
        stepsAnimation("initKey", "joiner", "completed")
        fetch('http://localhost:3006/api/joinerAsksForEncryptedInitKeyAndNonce', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                roomName: roomName,
                joinerToken: joinerToken
            })
        })
            .then(async response => {
                const data = await response.json();
                if (data.restartFront === true) {
                    restartFront()
                    return
                }
                if (response.status === 404) {//initKey not ready
                    setTimeout(() => {
                        joinerAsksForEncryptedInitKeyAndNonce()
                    }, 1500);
                    return;
                }
                if (!response.ok) {
                    return;
                }
                base64NonceIntoUint8Array(data.nonce); // the host will use the Uint8Array nonce to make his tempKey
                await joinerGeneratesTempKey();
                await joinerDecryptsInitKey(data.encryptedInitKey)
                showBorderEffect("joiner", "initKeyImgContainer")
            })
            .catch(error => {
                console.error('Error:', error)
                stepsAnimation("initKey", "joiner", "failed")
                alert("SecretCode1 is right?")
                setTimeout(() => {
                    location.reload()
                }, 5000);
            });
    }


    async function joinerDecryptsInitKey(base64Encrypted) {
        try {
            // Decode base64 to get nonce + ciphertext
            const encryptedWithNonce = Uint8Array.from(atob(base64Encrypted), c => c.charCodeAt(0));
            // Extract the nonce (first 12 bytes) and ciphertext (remaining bytes)
            const nonce = encryptedWithNonce.slice(0, 12); // First 12 bytes are the nonce
            const ciphertext = encryptedWithNonce.slice(12); // Rest is the ciphertext
            // Decrypt using the correct nonce and tempKey
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                tempKey,
                ciphertext
            );
            // Parse the decrypted data
            const initKeyJWK = JSON.parse(new TextDecoder().decode(decrypted));
            // Import the initKey as a CryptoKey
            initKeyCrypto = await crypto.subtle.importKey(
                'jwk',
                initKeyJWK,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );
            joinerEncryptsAndSendsDefKey();
        } catch (error) {
            stepsAnimation("initKey", "joiner", "failed")

            console.error("initKey decrypt error:", error);
            throw error;
        }
    }


    //6) The joiner starts a self-destruct timer, encrypts the defKey + random nonce using the decrypted initKey and sends it to the server. The first currentKey is the defKey derived with this nonce and the secretCode2.
    async function joinerEncryptsAndSendsDefKey() {
        try {
            stepsAnimation("defKey", "joiner", "completed");
            // Export defKey as raw (ArrayBuffer)
            const defKeyRaw = await crypto.subtle.exportKey('raw', defKey);
            // Generate a secure random nonce (16 bytes = 128 bits)
            const nonce = crypto.getRandomValues(new Uint8Array(16));
            cumulativeNonce = nonce //the first message: cumulativeNonce = nonce sent with deFkey
            await deriveNextCurrentDefKey(new Uint8Array(defKeyRaw)) //derive the key that encrypts the 1st message with cumulativeNonce and SC2
            // Concatenate defKey + nonce
            const defKeyWithNonce = new Uint8Array(defKeyRaw.byteLength + nonce.byteLength);
            defKeyWithNonce.set(new Uint8Array(defKeyRaw), 0);
            defKeyWithNonce.set(nonce, defKeyRaw.byteLength);
            // Encrypt the combined buffer with RSA-OAEP
            const encrypted = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                initKeyCrypto,
                defKeyWithNonce
            );
            // Convert to base64
            const base64EncryptedDefKey = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
            showBorderEffect("joiner", "defKeyImgContainer");
            // Send to server
            await fetch('http://localhost:3006/api/joinerSendsEncryptedDefKey', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    roomName,
                    joinerToken,
                    encryptedDefKey: base64EncryptedDefKey,
                })
            })
                .then(async response => {
                    const data = await response.json();
                    if (data.restartFront === true) { restartFront() }
                })
            timer("joiner", "start");
            joinerAsksForEncryptedSecret();
        } catch (error) {
            console.error("Error encrypting defKey:", error);
            stepsAnimation("defKey", "joiner", "failed");
        }
    }



    //7) The host polls every 1.5 s for the defKey encrypted by the initKey. When it arrives it is decrypted, the trailing 16-byte nonce is used with the secretCode2 to derivate the first currentKey, and the clean defKey is imported. The self-destruct timer is cleared.
    function hostAsksForEncryptedDefKey() {
        fetch('http://localhost:3006/api/hostAsksForEncryptedDefKey', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                roomName: roomName,
                hostToken: hostToken
            })
        })
            .then(async response => {
                const data = await response.json()
                if (data.restartFront === true) {
                    restartFront()
                    return
                }

                if (response.status === 404) {
                    //console.log(data.error); // "defKey not ready"
                    setTimeout(() => {
                        hostAsksForEncryptedDefKey()
                    }, 1500)
                    return
                }
                if (!response.ok) {
                    stepsAnimation("defKey", "host", "failed");
                    throw new Error(`HTTP ${response.status}`);
                }
                return data;
            })
            .then(data => {
                if (data?.encryptedDefKey) {
                    hostDecryptsDefKey(data.encryptedDefKey);
                    showBorderEffect("host", "defKeyImgContainer");
                }
            })
            .catch(error => {
                console.error('Error requesting defKey:', error);
            });
    }

    // Decrypt the ciphertext, strip the trailing 16-byte nonce and import the AES key.
    async function hostDecryptsDefKey(base64EncryptedDefKey) {
        try {
            // 1. base64 → Uint8Array
            const encryptedData = Uint8Array.from(
                atob(base64EncryptedDefKey),
                c => c.charCodeAt(0)
            );
            // 2. RSA-OAEP decryption (returns defKey || nonce)
            const decryptedWithNonce = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                keyPair.privateKey,
                encryptedData
            );
            // 3. Convert to Uint8Array and drop the last 16 bytes
            const fullArray = new Uint8Array(decryptedWithNonce);
            const NONCE_LENGTH = 16;
            if (fullArray.byteLength <= NONCE_LENGTH) {
                throw new Error('Decrypted payload too short – missing nonce');
            }
            const defKeyRaw = fullArray.slice(0, -NONCE_LENGTH);
            cumulativeNonce = fullArray.slice(-NONCE_LENGTH); //the first message: cumulativeNonce = nonce sent with deFkey
            defKey = await crypto.subtle.importKey(
                'raw',
                defKeyRaw,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );
            await deriveNextCurrentDefKey(new Uint8Array(defKeyRaw)) //the first message is encrypted by defKey derived using SC2 and cumulativeNonce


            timer("host", "stop");
            hostEncryptsTheSecret(defKey);
            stepsAnimation("validated", "host", "completed");
        } catch (error) {
            console.error('Decryption/import error:', error);
            stepsAnimation("defKey", "host", "failed");
        }
    }

    //8)The host Encrypts the hash of secretCode2 using the defKey and sends it to the server.
    async function hostEncryptsTheSecret() {
        try {
            if (!defKey) {
                console.error("defKey non disponibile. Attendere...");
                return;
            }
            // Convert secret (string) to ArrayBuffer
            const encoder = new TextEncoder();
            const dataToHash = encoder.encode(secretCode2);
            //Hash
            const hashBuffer = await crypto.subtle.digest('SHA-256', dataToHash);
            const secretToEncrypt = new Uint8Array(hashBuffer)
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            // Encrypt with defKey (AES-GCM)
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce },
                defKey,
                secretToEncrypt
            );
            // Concatenate nonce + ciphertext
            const result = new Uint8Array(nonce.byteLength + encrypted.byteLength);
            result.set(nonce, 0);
            result.set(new Uint8Array(encrypted), nonce.byteLength);
            // Convert to base64 for sending
            const base64EncryptedHash = btoa(String.fromCharCode(...result));
            showBorderEffect("host", "lockStatusImgContainer")
            hostSendsEncryptedSecret(base64EncryptedHash);
            defKey = null
        } catch (error) {
            stepsAnimation("validated", "host", "failed")
            console.error("secret crypto error:", error);
        }
    }


    function hostSendsEncryptedSecret(base64EncryptedHash) {
        fetch('http://localhost:3006/api/hostSendsEncryptedSecret', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                roomName: roomName,
                hostToken: hostToken,
                encryptedSecret: base64EncryptedHash
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.restartFront === true) { restartFront() }
                stepsAnimation("chat", "host", "completed")
                updateDynamicElements("chatPage")
                connectChatWebSocket();
            })
            .catch(error => {
                stepsAnimation("validated", "host", "failed")

            });
    }
    //9)The joiner ask for the encrypted hash of SecretCode2, decrypts it, compares it. If matches, the processus is validated and the joiner timer cleared.
    async function joinerAsksForEncryptedSecret() {
        try {
            stepsAnimation("validated", "joiner", "completed")
            const response = await fetch('http://localhost:3006/api/joinerAsksForEncryptedSecret', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    roomName: roomName,
                    joinerToken: joinerToken
                })
            });
            if (response.status === 404) { //encrypted secret is not ready
                setTimeout(() => {
                    joinerAsksForEncryptedSecret()
                }, 1500);
                return;
            }
            const data = await response.json();
            if (data.restartFront === true) { restartFront() }

            if (!data.encryptedSecret) {
                throw new Error("Encrypted secret not found in server response");
            }
            showBorderEffect("joiner", "lockStatusImgContainer")

            joinerDecryptsTheSecret(data.encryptedSecret)
        } catch (error) {
            stepsAnimation("validated", "joiner", "failed")
        }
    }


    async function joinerDecryptsTheSecret(base64EncryptedSecret) {
        try {
            // Decode base64 to get nonce + ciphertext
            const encryptedWithNonce = Uint8Array.from(atob(base64EncryptedSecret), c => c.charCodeAt(0));
            // Extract nonce (first 12 bytes) and ciphertext (remaining bytes)
            const nonce = encryptedWithNonce.slice(0, 12);
            const ciphertext = encryptedWithNonce.slice(12);
            // Decrypt using defKey and the extracted nonce
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                defKey,
                ciphertext
            );
            const receivedSecretHash = new Uint8Array(decrypted)
            joinerValidatesTheHost(receivedSecretHash)
        } catch (error) {
            stepsAnimation("validated", "joiner", "failed")
            throw error;
        }
    }

    async function joinerValidatesTheHost(receivedSecretHash) {
        const encoder = new TextEncoder();
        const myHashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(secretCode2));
        const myHash = new Uint8Array(myHashBuffer)
        const a = receivedSecretHash;
        const b = myHash;
        if (a.length === b.length && a.toString() === b.toString()) {
            stepsAnimation("chat", "joiner", "completed")
            timer("joiner", "stop")
            alert("host is certified!")
            defKey = null
            updateDynamicElements("chatPage")
            connectChatWebSocket();
        } else {
            alert("host is not certified")
            deleteRoom()
            stepsAnimation("chat", "joiner", "failed")
            setTimeout(() => {
                location.reload()
            }, 1000);
        }
    }

    //--------------------------------Functional functions (chat part)
    // WebRTC VoIP — Audio-only peer-to-peer calls, Audio is encrypted in transit by DTLS-SRTP (built into WebRTC). Signaling (offer/answer/ICE) is sent over the existing chat WebSocket. The server only relays signaling — it never sees media or keys.
    let currentDefKey = null
    let chatWS = null;
    let lastSentFileInfo = null;
    let localStream = null;              // Local microphone MediaStream
    let peerConnection = null;           // RTCPeerConnection for the current call
    let isInCall = false;                // Whether the user is currently in a call
    let incomingOffer = null;            // Stores an incoming SDP offer until the user accepts
    let pendingCandidates = [];          // ICE candidates buffered until remote description is set
    let ringingTimeout = null;           // Timeout that auto-declines unanswered calls after 60s
    let remoteAudioElement = null;       // <audio> element that plays the remote party's audio
    let iceServers = null  // ICE servers used for NAT traversal. Stun or turn


    function connectChatWebSocket() {
        //console.log("WS OPENING WITH:", roomName, hostToken, joinerToken);
        if (chatWS) {
            try { chatWS.close(); } catch (e) { }
        } let token
        if (userName == "host") {
            token = hostToken
        } else if (userName == "joiner") {
            token = joinerToken
        }
        const wsUrl = `ws://localhost:3006/ws?roomName=${roomName}&token=${token}`;
        chatWS = new WebSocket(wsUrl); //upgrade to websocket
        chatWS.onopen = () => {
            //console.log('✅ Chat WebSocket connected (real-time, no polling)');
        };
        chatWS.onmessage = async (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'webrtc-signaling') {
                await handleSignalingMessage(data.payload);
            } else {
                await decryptTheMessage(data.message || data);
            }
        };
        chatWS.onclose = () => {
            console.warn('WebSocket closed. Reconnecting in 2s...');
            setTimeout(connectChatWebSocket, 2000);
        };
        chatWS.onerror = (err) => console.error('WebSocket error:', err);
    }

    //---------------------------VoIP  

        /*
(startCall)
    Caller opens mic, creates PC, sends offer (SDP), then sends candidates as they gather. 

(handleSignalingMessage)
    Callee buffers caller's candidates and saves incomingOffer.

(acceptIncomingCall)
    Callee answers: creates PC, sets caller's offer as remoteDescription, then adds buffered candidates, gets mic & adds tracks, 
    creates answer (which negotiates codec), sets it as localDescription, sends answer, then sends own candidates as they gather.

(handleSignalingMessage)
    Caller sets callee's answer as remoteDescription, then adds buffered callee candidates.
    */


    async function fetchIceServers() { //ask for STUN/TURN urls
        if (iceServers) return iceServers;
        const token = userName === "host" ? hostToken : joinerToken;
        if (!token || !roomName) throw new Error("Not authenticated for calls");
        const response = await fetch(`http://localhost:3006/api/getTurnCredentials?roomName=${encodeURIComponent(roomName)}&token=${encodeURIComponent(token)}`);
        if (!response.ok) throw new Error("Failed to fetch TURN credentials");
        const data = await response.json();
        iceServers = data;
        return iceServers;
    }


    async function startCall() { //gets local mic, create RTCPeerConnection, and send candidates and offer (sdp)
        if (isInCall) return;
        try {
            localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
            const ice = await fetchIceServers(); //STUN and TURN URLs
            peerConnection = new RTCPeerConnection(ice);
            peerConnection.onicecandidate = e => { // ice is used to get my(caller) addresses: host, srflx (STUN), relay (TURN)
                if (e.candidate) {
                    //console.log("CANDIDATE:", e.candidate.candidate);
                    sendSignaling({ type: 'candidate', candidate: e.candidate }); //signaling my(caller) addresses (where to reach me)
                }
            };
            peerConnection.oniceconnectionstatechange = () => {
                //console.log('ICE connection state:', peerConnection.iceConnectionState);
            };
            peerConnection.onicegatheringstatechange = () => {
                //console.log('ICE gathering state:', peerConnection.iceGatheringState);
            };
            peerConnection.ontrack = e => {
                let audioEl = document.getElementById("remoteAudio");
                if (!audioEl) {
                    audioEl = new Audio();
                    audioEl.id = "remoteAudio";
                    audioEl.autoplay = true;
                    document.body.appendChild(audioEl);
                }
                audioEl.srcObject = e.streams[0];
                audioEl.play().catch(err => console.error("Caller audio failed:", err));
            };
            localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
            const offer = await peerConnection.createOffer();
            await peerConnection.setLocalDescription(offer);
            sendSignaling({ type: 'offer', sdp: offer }); //signaling how to communicate with me (codecs, media format, encryption format..)
            isInCall = true;
            updateCallUI();
            ringingTimeout = setTimeout(() => {
                if (isInCall && peerConnection) {
                    //console.log('Call timeout - no answer');
                    hangUp(true);
                }
            }, 60000);
        } catch (err) {
            console.error(err);
            alert("Microphone access is required to make calls.");
        }
    }


    function sendSignaling(payload) {
        if (chatWS?.readyState === WebSocket.OPEN) {
            chatWS.send(JSON.stringify({
                type: 'webrtc-signaling',
                payload
            }));
        }
    }

    async function handleSignalingMessage(payload) { //signaling message received
        if (payload.type === 'offer') {
            incomingOffer = payload;
            document.getElementById("incomingCallBox").style.display = "block";
            document.getElementById("incomingCallBox").style.position = "absolute";
            document.getElementById("incomingCallBox").style.justifySelf = "center";
            document.getElementById("incomingCallBox").style.top = "50px";
            // Auto-decline after 60 seconds of ringing
            ringingTimeout = setTimeout(() => {
                if (incomingOffer) {
                    //console.log('Ringing timeout - auto declining');
                    declineIncomingCall();
                }
            }, 60000);
            return;
        }
        if (payload.type === 'answer' && peerConnection) { //caller received answer: he saves sdp of the callee
            if (ringingTimeout) {
                clearTimeout(ringingTimeout);
                ringingTimeout = null;
            }
            await peerConnection.setRemoteDescription(new RTCSessionDescription(payload.sdp)); //save the peer contact information: codec, fingerprint DTLS..
            // Add buffered ICE candidates that arrived before the answer
            for (const candidate of pendingCandidates) {
                try {
                    await peerConnection.addIceCandidate(new RTCIceCandidate(candidate)); //register where to reach the callee (host, srflx, relay)
                } catch (e) {
                    console.warn('Failed to add buffered ICE candidate:', e);
                }
            }
            pendingCandidates = [];
            return;
        }
        if (payload.type === 'candidate') {
            // Only add ICE candidates once the remote description is set.
            // Otherwise buffer them for later (they arrive when callee hasn't accepted yet / caller hasn't received answer yet).
            if (peerConnection && peerConnection.remoteDescription) {
                try {
                    await peerConnection.addIceCandidate(new RTCIceCandidate(payload.candidate)); // register where to reach the other peer
                } catch (e) {
                    console.warn('Failed to add ICE candidate:', e);
                }
            } else {
                pendingCandidates.push(payload.candidate); //buffer
            }
            return;
        }
        if (payload.type === 'decline' || payload.type === 'hangup') {
            hangUp(true);
        }
    }

    function declineIncomingCall() {
        if (ringingTimeout) {
            clearTimeout(ringingTimeout);
            ringingTimeout = null;
        }
        sendSignaling({ type: 'decline' });
        incomingOffer = null;
        pendingCandidates = [];
        document.getElementById("incomingCallBox").style.display = "none";
    }



    async function acceptIncomingCall() { //creates RTCPeerConnection, sets the offer as remote description, applies buffered candidates, add local mic, sends candidates and sdp
        if (!incomingOffer) return;
        if (ringingTimeout) {
            clearTimeout(ringingTimeout);
            ringingTimeout = null;
        }
        try {
            const ice = await fetchIceServers();
            peerConnection = new RTCPeerConnection(ice);// ice is used to get my (callee) addresses: host, srflx (STUN), relay (TURN)
            // Set up ontrack FIRST to avoid missing remote stream
            peerConnection.ontrack = e => {
                //console.log("REMOTE TRACK:", e.streams[0]?.getTracks());
                if (!e.streams[0]) {
                    console.error("No remote stream received!");
                    return;
                }
                if (!remoteAudioElement) {
                    remoteAudioElement = new Audio();
                    remoteAudioElement.autoplay = true;
                    document.body.appendChild(remoteAudioElement);
                }
                remoteAudioElement.srcObject = e.streams[0];
                remoteAudioElement.play().catch(err => console.error("Callee audio failed:", err));
            };
            peerConnection.oniceconnectionstatechange = () => {
                //console.log('ICE connection state:', peerConnection.iceConnectionState);
            };
            peerConnection.onicegatheringstatechange = () => {
                //console.log('ICE gathering state:', peerConnection.iceGatheringState);
            };
            // Set the caller's offer as our remote description
            await peerConnection.setRemoteDescription(new RTCSessionDescription(incomingOffer.sdp));
            // Apply buffered ICE candidates that arrived before the callee answered
            for (const candidate of pendingCandidates) {
                try {
                    await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
                } catch (e) {
                    console.warn('Failed to add buffered ICE candidate:', e);
                }
            }
            pendingCandidates = [];
            localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
            //console.log("LOCAL TRACKS:", localStream.getTracks());
            localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
            peerConnection.onicecandidate = e => {
                if (e.candidate) {
                    //console.log("CANDIDATE:", e.candidate.candidate);
                    sendSignaling({ type: 'candidate', candidate: e.candidate });
                }
            };
            // Create and send the SDP answer
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            sendSignaling({ type: 'answer', sdp: answer });
            incomingOffer = null;
            isInCall = true;
            document.getElementById("incomingCallBox").style.display = "none";
            updateCallUI();
        } catch (err) {
            console.error('Failed to accept call:', err);
            alert("Failed to accept the call.");
            hangUp(true);
        }
    }


    function hangUp(remoteInitiated = false) {
        if (ringingTimeout) {
            clearTimeout(ringingTimeout);
            ringingTimeout = null;
        }
        if (peerConnection) peerConnection.close();
        if (localStream) localStream.getTracks().forEach(t => t.stop());
        if (remoteAudioElement) {
            remoteAudioElement.remove();
            remoteAudioElement = null;
        }
        peerConnection = null;
        localStream = null;
        isInCall = false;
        incomingOffer = null;
        pendingCandidates = [];
        document.getElementById("incomingCallBox").style.display = "none";
        updateCallUI();
        if (!remoteInitiated) {
            sendSignaling({ type: 'hangup' });
        }
    }

    // Update the call button text and color based on call state.
    function updateCallUI() {
        const btn = document.getElementById("callBtn");
        btn.textContent = isInCall ? " Hang up" : " Call";
        btn.style.backgroundColor = isInCall ? c25 : "";
    }

    document.getElementById("acceptCallBtn").addEventListener("click", acceptIncomingCall);
    document.getElementById("declineCallBtn").addEventListener("click", declineIncomingCall);


    // -----------------chat part

    document.getElementById("sendFileBtn").addEventListener("click", () => {
        const fileInput = document.getElementById("fileInput");
        fileInput.value = "";           // allow to select again the last file
        fileInput.click();
    });

    document.getElementById("fileInput").addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const originalBtnText = document.getElementById("sendFileBtn").textContent;
        const btn = document.getElementById("sendFileBtn");
        btn.textContent = "📤 Loading...";
        btn.disabled = true;
        const reader = new FileReader();
        reader.onerror = () => {
            console.error("Cannot read file");
            alert("Cannot read file");
            resetFileButton(originalBtnText);
        };
        reader.onload = async () => {
            try {
                const uint8Array = new Uint8Array(reader.result);
                const ext = file.name.split('.').pop()?.toLowerCase() || "bin";
                //console.log(`📄 File ready → ${file.name} (${uint8Array.byteLength} byte) .${ext}`);
                lastSentFileInfo = {
                    bytes: uint8Array,
                    ext: ext,
                    name: file.name
                };
                await encryptTheMessage("file", uint8Array, ext);
            } catch (err) {
                console.error(err);
                alert("Attachment Error" + err);
            } finally {
                resetFileButton(originalBtnText);
            }
        };
        reader.readAsArrayBuffer(file);
    });

    function resetFileButton(originalText) {
        const btn = document.getElementById("sendFileBtn");
        btn.textContent = originalText;
        btn.disabled = false;
    }




    document.getElementById("sendMsgBtn").addEventListener("click", () => { encryptTheMessage("msg", document.getElementById("messageInput").value) })
    document.getElementById("destroyChatBtn").addEventListener("click", deleteRoom)
    document.getElementById("saveChatBtn").addEventListener("click", saveChat)
    document.getElementById("callBtn").addEventListener("click", () => {
        if (isInCall) {
            hangUp();
        } else {
            startCall();
        }
    });



    async function hostSendsMessage(base64EncryptedMsg) {
        try {
            const response = await fetch('http://localhost:3006/api/hostSendsMessage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    roomName,
                    hostToken,
                    message: base64EncryptedMsg
                })
            });
            if (response.status == 403) {
                alert("This chat is lost or deleted.")
                location.reload()
                return false
            }
            if (response.status === 429) {
                alert("Too many pending messages, please wait...");
                return false;
            }
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Send failed');
            }
            const data = await response.json();
            sendOk = true


            return true;

        } catch (error) {
            console.error("Error:", error);
            return false;
        }
    }

    async function joinerSendsMessage(base64EncryptedMsg) {
        //console.log(roomName, joinerToken, base64EncryptedMsg)
        try {
            const response = await fetch('http://localhost:3006/api/joinerSendsMessage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    roomName,
                    joinerToken,
                    message: base64EncryptedMsg
                })
            });
            if (response.status == 403) {
                alert("This chat is lost or deleted.")
                location.reload()
                return false
            }
            if (response.status === 429) {
                alert("Too many pending messages, please wait...");
                return false;
            }
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Send failed');
            }
            const data = await response.json();
            sendOk = true



            return true;
        } catch (error) {
            console.error(error);
            return false;
        }
    }

    async function deriveNextCurrentDefKey(nextAesRaw) {
        // Build dynamic salt: secretCode2 + cumulative nonce (16 bytes)
        const secretBytes = new TextEncoder().encode(secretCode2)
        let salt = new Uint8Array(secretBytes.length + 16);
        salt.set(secretBytes)
        salt.set(cumulativeNonce, secretBytes.length)
        const hash = await argon2.hash({
            pass: nextAesRaw,
            salt: salt,
            time: 3,
            mem: 32768,
            hashLen: 32,
            parallelism: 1,
            type: argon2.Argon2id
        })
        const newKey = await crypto.subtle.importKey(
            "raw",
            hash.hash,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        )
        currentDefKey = newKey
        return currentDefKey
    }


    function generatePadding(length) {
        if (length <= 0) return new Uint8Array(0);
        const allowedCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const allowedLen = allowedCharacters.length;
        const paddingBytes = new Uint8Array(length);
        const CHUNK_SIZE = 65536;                    //  getRandomValues limit
        let offset = 0;
        const tempChunk = new Uint8Array(CHUNK_SIZE);
        while (offset < length) {
            const remaining = length - offset;
            const currentChunkSize = Math.min(CHUNK_SIZE, remaining);
            const chunkView = tempChunk.subarray(0, currentChunkSize);
            crypto.getRandomValues(chunkView);
            for (let i = 0; i < currentChunkSize; i++) {
                const randomIndex = chunkView[i] % allowedLen;
                paddingBytes[offset + i] = allowedCharacters.charCodeAt(randomIndex);
            }
            offset += currentChunkSize;
        }
        return paddingBytes;
    }


    function uint8ToBase64(u8) {
        const CHUNK = 0x8000; // 32768 safe for apply
        let i = 0;
        const parts = [];
        while (i < u8.length) {
            parts.push(String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK)));
            i += CHUNK;
        }
        return btoa(parts.join(''));
    }


    async function encryptTheMessage(msgOrFileOrCall, content, fileExt = null) {
        let finalPlaintext;
        if (msgOrFileOrCall === "msg") {
            if (content.length === 0) {
                alert("The message is empty.");
                return;
            }
            const charactersNeededForPadding = 423 - 3 - content.length; // 3 chars prefix (content.length)
            const extraPaddingLength = Math.floor(Math.random() * 80);
            const paddingBytes = generatePadding(charactersNeededForPadding + extraPaddingLength);
            const messageLength3Chars = String(content.length).padStart(3, "0");
            const paddingString = new TextDecoder().decode(paddingBytes)
            const fullString = messageLength3Chars + content + paddingString;
            finalPlaintext = new TextEncoder().encode(fullString);
        }
        else if (msgOrFileOrCall === "file") {
            const MAX_BYTES = 1048576 - 11; //1 mb - prefix size (11:4 for extension + 7 for length) pdf-0048576 or jpeg1018576
            if (!content) {
                alert("No file content provided.");
                return;
            }
            if (!(content instanceof Uint8Array)) {
                alert("Unsupported file content type.");
                return;
            }
            if (content.byteLength > MAX_BYTES) {
                alert("File too big! Maximum ~1 MB.");
                return;
            }
            // Save original bytes and sanitized extension BEFORE building finalPlaintext ensures download uses the exact original bytes (no prefix/padding)
            const rawExt = (fileExt || "bin").toString();
            lastSentFileInfo = { bytes: content.slice(0), ext: rawExt.toLowerCase() };
            const extSource = (fileExt || lastSentFileInfo?.ext || "bin").toString();
            const ext = extSource.replace(/[^a-zA-Z0-9]/g, '').slice(0, 4).toLowerCase().padEnd(4, "-");
            const lenStr = String(content.byteLength).padStart(7, "0");
            const prefixStr = ext + lenStr; // 11 chars pdf-0000123
            const prefixBytes = new TextEncoder().encode(prefixStr); // 11 bytes [112, 100, 102, 45, 48, 48, 48, 48, 48, 49, 50, 51]
            const FIXED_SIZE = 1048576; // 1 MiB exact
            const usedBytes = prefixBytes.length + content.byteLength;
            if (usedBytes > FIXED_SIZE) {
                alert("File too big! Maximum ~1 MB.");
                return;
            }
            const neededPadding = FIXED_SIZE - usedBytes;
            const paddingBytes = generatePadding(neededPadding);
            // Build finalPlaintext
            finalPlaintext = new Uint8Array(FIXED_SIZE);
            finalPlaintext.set(prefixBytes, 0);
            finalPlaintext.set(content, prefixBytes.length);
            finalPlaintext.set(paddingBytes, prefixBytes.length + content.byteLength);
        }
        try {
            const nextAesKey = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
            const nextAesRaw = new Uint8Array(await crypto.subtle.exportKey("raw", nextAesKey));
            const derivationNonce = crypto.getRandomValues(new Uint8Array(16));
            const payload = new Uint8Array(finalPlaintext.byteLength + 32 + 16);
            payload.set(finalPlaintext, 0);
            payload.set(nextAesRaw, finalPlaintext.byteLength); // nextAesRaw is 32 bytes
            payload.set(derivationNonce, finalPlaintext.byteLength + 32);/*
            Case "msg": payload = [3-digit length + message + random padding] + [32 byte next AES key] + [16 byte derivationNonce]
            Case "file": payload = [4-char ext + 7-digit length + file bytes + padding up to 1 MiB] + [32 byte next AES key] + [16 byte derivationNonce]*/
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                currentDefKey,
                payload
            );
            const encryptedU8 = new Uint8Array(encrypted);
            const result = new Uint8Array(iv.byteLength + encryptedU8.byteLength);
            result.set(iv, 0);
            result.set(encryptedU8, iv.byteLength);
            const base64EncryptedMsg = uint8ToBase64(result);
            if (userName === "host") {
                await hostSendsMessage(base64EncryptedMsg);
            } else {
                await joinerSendsMessage(base64EncryptedMsg);
            }
            if (sendOk) {
                if (msgOrFileOrCall === "file" && lastSentFileInfo) {
                    addFileMessage(lastSentFileInfo.bytes, lastSentFileInfo.ext, "me");
                }
                if (msgOrFileOrCall === "msg") {
                    let message = document.getElementById("messageInput").value;
                    addTextMessage(message, "me");
                }
                sendOk = false;
                // ratchet update for cumulativeNonce (maintain 16 bytes)
                if (!cumulativeNonce || cumulativeNonce.byteLength === 0) {
                    cumulativeNonce = derivationNonce;
                } else {
                    const combined = new Uint8Array(32);
                    combined.set(cumulativeNonce, 0);
                    combined.set(derivationNonce, 16);
                    const hash = await crypto.subtle.digest("SHA-256", combined);
                    cumulativeNonce = new Uint8Array(hash).slice(0, 16);
                }
                currentDefKey = await deriveNextCurrentDefKey(nextAesRaw);
            }
        } catch (error) {
            console.error("Encryption failed:", error);
            alert("Failed to send message/file");
        }
    }


    async function decryptTheMessage(base64EncryptedMsg) {
        try {
            const encryptedWithIv = Uint8Array.from(atob(base64EncryptedMsg), c => c.charCodeAt(0));
            const iv = encryptedWithIv.slice(0, 12);
            const ciphertext = encryptedWithIv.slice(12);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                currentDefKey,
                ciphertext
            );
            const full = new Uint8Array(decrypted);
            const totalFixed = 32 + 16; //decrypted payload structure: [content] + [32 byte next AES key] + [16 byte derivationNonce]
            const msgLength = full.byteLength - totalFixed;
            if (msgLength < 0) throw new Error("Corrupted payload");
            const msgBytes = full.slice(0, msgLength);           // payload of message/file: [3-digit length + message + random padding] or [4-char ext + 7-digit length + file bytes + padding up to 1 MiB]
            const nextAesRaw = full.slice(msgLength, msgLength + 32);
            const derivationNonce = full.slice(msgLength + 32);
            const first3 = new TextDecoder("utf-8", { fatal: false }).decode(msgBytes.slice(0, 3));
            if (/^\d{3}$/.test(first3) && first3 !== "000") {
                // Text message path
                const paddedMsg = new TextDecoder().decode(msgBytes);
                const realLen = parseInt(first3, 10);
                if (realLen < 0 || realLen > msgBytes.byteLength - 3) throw new Error("Invalid message length");
                const realMessage = paddedMsg.slice(3, 3 + realLen);
                addTextMessage(realMessage, "partner");
                if (!cumulativeNonce || cumulativeNonce.byteLength === 0) {
                    cumulativeNonce = derivationNonce;
                } else {
                    const combined = new Uint8Array(32);
                    combined.set(cumulativeNonce, 0);
                    combined.set(derivationNonce, 16);
                    const hash = await crypto.subtle.digest("SHA-256", combined);
                    cumulativeNonce = new Uint8Array(hash).slice(0, 16);
                }
                currentDefKey = await deriveNextCurrentDefKey(nextAesRaw);
                return;
            } else {
                // File path
                const prefixStr = new TextDecoder().decode(msgBytes.slice(0, 11));
                const extRaw = prefixStr.slice(0, 4);
                const lenStr = prefixStr.slice(4, 11);
                const realLen = parseInt(lenStr, 10);
                if (isNaN(realLen) || realLen <= 0 || realLen > msgBytes.byteLength - 11) {
                    console.error("Invalid file length. Expected:", realLen, "Available:", msgBytes.byteLength - 11);
                    throw new Error("Invalid file length");
                }
                const fileBytes = msgBytes.slice(11, 11 + realLen);
                const safeExt = (extRaw || "bin").toString().replace(/[^a-zA-Z0-9]/g, '').slice(0, 4) || 'bin';
                addFileMessage(fileBytes, safeExt || "bin", "partner");
                // Only update ratchet after successful handling
                if (!cumulativeNonce || cumulativeNonce.byteLength === 0) {
                    cumulativeNonce = derivationNonce;
                } else {
                    const combined = new Uint8Array(32);
                    combined.set(cumulativeNonce, 0);
                    combined.set(derivationNonce, 16);
                    const hash = await crypto.subtle.digest("SHA-256", combined);
                    cumulativeNonce = new Uint8Array(hash).slice(0, 16);
                }
                currentDefKey = await deriveNextCurrentDefKey(nextAesRaw);
                return;
            }

        } catch (error) {
            console.error("Decryption failed:", error);
        }
    }

    function showFile(fileBytes, ext, user) {
        const ul = document.getElementById('ulChat');
        const mimeMap = {
            png: "image/png",
            jpg: "image/jpeg",
            jpeg: "image/jpeg",
            gif: "image/gif",
            webp: "image/webp",
            pdf: "application/pdf"
        };
        const mimeType = mimeMap[ext.toLowerCase()] || "application/octet-stream";
        const blob = new Blob([fileBytes], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = url;
        a.download = `file.${ext}`;
        if (mimeType.startsWith("image/")) {
            const img = document.createElement("img");
            img.src = url;
            img.style.maxWidth = "80%";
            img.style.borderRadius = "8px";
            img.style.margin = "5px 0";
            a.appendChild(img);
        } else {
            a.textContent = `📎 Download ${ext.toUpperCase()}`;
            a.style.color = c9;
            a.style.textDecoration = "underline";
        }
        li.appendChild(a);
        if (user === "partner") {
            li.style.color = c25;
            li.style.textShadow = "1px 1px white";
        } else {
            li.style.color = c26;
            li.style.textShadow = "1px 1px white";
        }

        ul.appendChild(li);
    }

    function addTextMessage(text, user) {
        chatMessages.push({
            type: "text",
            text,
            user
        });
        showMsg(text, user);
    }

    function addFileMessage(fileBytes, ext, user) {
        chatMessages.push({
            type: "file",
            bytes: Array.from(fileBytes),
            ext,
            user
        });
        showFile(fileBytes, ext, user);
    }



    function showMsg(message, user) {
        const ul = document.getElementById('ulChat');
        const li = document.createElement('li');
        li.textContent = message;
        li.style.fontSize = "larger";

        if (user === "partner") {
            li.style.color = c25;
            li.style.textShadow = "1px 1px white";
        } else {
            li.style.color = c26;
            li.style.textShadow = "1px 1px white";
        }

        ul.appendChild(li);
    }



    async function deleteRoom() {
        let token
        if (userName == "host") {
            token = hostToken
        } else if (userName == "joiner") {
            token = joinerToken
        }
        try {
            await dbDelete(roomName).catch(() => {}) // remove from IndexedDB
            const res = await fetch('http://localhost:3006/api/deleteRoom', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, roomName })
            });
            if (res.status === 403 || res.status === 200) {
                alert("This chat is lost or deleted.")
                location.reload()
                return
            }
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error);
            }
            return true;
        } catch (error) {
            alert("Delete failed:", error);
            return false;
        }
    }
}

app()
