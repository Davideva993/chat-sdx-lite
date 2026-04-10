
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
    console.log("Argon2:", typeof argon2 !== "undefined" ? "ok" : "error");
    const dynamicElements = document.getElementsByClassName("dynamic")
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

    updateDynamicElements("landingPage")
    hostBtnStart.addEventListener("click", () => updateDynamicElements("hostPage"))
    joinBtnStart.addEventListener("click", () => updateDynamicElements("joinPage"))
    backButton.addEventListener("click", () => updateDynamicElements("landingPage"))
    hostBtnEnd.addEventListener("click", hostSetupAndRegisterARoom)
    joinBtnEnd.addEventListener("click", joinerSetupAndFindsRoom)
    reloadButton.addEventListener("click", () => { location.reload() })



    //--------------------------------------Design functions
    function updateDynamicElements(classToShow) {

        for (let i = 0; i < dynamicElements.length; i++) {
            if (!dynamicElements[i].classList.contains(classToShow)) {
                dynamicElements[i].style.display = "none";
            } else {
                dynamicElements[i].style.display = "";
            }
        }
        const label = document.querySelector('label[for="roomNameInput"]')
        if (classToShow == "chatPage") {
            document.getElementById("centralSection").style.height = "60vh"
        }
        else if (classToShow == "hostPage") {
            document.getElementById("roomNameInput").readOnly = true;
            document.getElementById("roomNameInput").style.background = "grey";
            document.getElementById("roomNameInput").style.outline = "none";
            document.getElementById("roomNameInput").value = "";
            label.textContent = "Room name (will be auto-filled)"
        }
        else if (classToShow == "joinPage") {
            document.getElementById("roomNameInput").readOnly = false;
            document.getElementById("roomNameInput").style.background = "white";
            document.getElementById("roomNameInput").style.outline = "initial";

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
                    document.getElementById("initKeyHostLegend").textContent = "Working on it..."
                    document.getElementById("tempKeyHostLegend").textContent = "TempKey, a symmetric AES-GCM key, successfully generated from the secret word 1 and using Argon2."
                    document.getElementById("tempKeyHostImg").classList.add("stepCompleted")
                }
                if (nextStep == "defKey") {
                    document.getElementById("defKeyHostLegend").textContent = "Working on it..."
                    document.getElementById("initKeyHostLegend").textContent = "initKey, a public assymetric RSA-OAEP key, was encrypted by tempKey and successfully sent to the server."
                    document.getElementById("initKeyHostImg").classList.add("stepCompleted")
                }
                if (nextStep == "validated") {
                    document.getElementById("lockStatusHostLegend").textContent = "Working on it..."
                    document.getElementById("defKeyHostLegend").textContent = "defKey, a symmetric AES-GCM key encrypted by initKey, was received and decrypted."
                    document.getElementById("defKeyHostImg").classList.add("stepCompleted")
                }
                if (nextStep == "chat") {
                    document.getElementById("lockStatusHostLegend").textContent = "The secret word 2 encrypted by defKey successfully sent to the server. If the joiner validates it, the chat starts."
                    document.getElementById("lockStatusHostImg").src = "./assets/locked.webp"
                }
            }
            else if (user == "joiner") {
                if (nextStep == "tempKey") {
                    document.getElementById("tempKeyJoinerLegend").textContent = "Working on it..."
                }
                if (nextStep == "initKey") {
                    document.getElementById("initKeyJoinerLegend").textContent = "Working on it..."
                    document.getElementById("tempKeyJoinerLegend").textContent = "TempKey, a symmetric AES-GCM key, successfully generated from the secret word 1 and using Argon2."
                    document.getElementById("tempKeyJoinerImg").classList.add("stepCompleted")
                }
                if (nextStep == "defKey") {
                    document.getElementById("defKeyJoinerLegend").textContent = "Working on it..."
                    document.getElementById("initKeyJoinerLegend").textContent = "initKey, the host public assymetric RSA-OAEP key encrypted by tempKey, was received and decrypted."
                    document.getElementById("initKeyJoinerImg").classList.add("stepCompleted")
                }
                if (nextStep == "validated") {
                    document.getElementById("lockStatusJoinerLegend").textContent = "Working on it..."
                    document.getElementById("defKeyJoinerLegend").textContent = "defKey, a symmetric AES-GCM key, was encrypted by initKey and sent to the server."
                    document.getElementById("defKeyJoinerImg").classList.add("stepCompleted")
                }
                if (nextStep == "chat") {
                    document.getElementById("lockStatusJoinerLegend").textContent = "The secret word 2 encrypted by defKey received and successfully validated. The chat can begin."
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
        fetch('http://localhost:3001/api/hostRegistersRoom', {
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
        fetch('http://localhost:3001/api/hostAsksForJoiner', {
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
        fetch('http://localhost:3001/api/joinerFindsRoom', {
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
        fetch('http://localhost:3001/api/hostSendsEncryptedInitKeyAndNonce', {
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
        fetch('http://localhost:3001/api/joinerAsksForEncryptedInitKeyAndNonce', {
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
            await fetch('http://localhost:3001/api/joinerSendsEncryptedDefKey', {
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
        fetch('http://localhost:3001/api/hostAsksForEncryptedDefKey', {
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
                    console.log(data.error); // "defKey not ready"
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
        fetch('http://localhost:3001/api/hostSendsEncryptedSecret', {
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
            const response = await fetch('http://localhost:3001/api/joinerAsksForEncryptedSecret', {
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

    let currentDefKey = null
    let chatWS = null;
    let lastSentFileInfo = null;



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
                console.log(`📄 File ready → ${file.name} (${uint8Array.byteLength} byte) .${ext}`);
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


    function connectChatWebSocket() {
        if (chatWS && chatWS.readyState === WebSocket.OPEN) return;
        let token
        if (userName == "host") {
            token = hostToken
        } else if (userName == "joiner") {
            token = joinerToken
        }
        const wsUrl = `ws://localhost:3001?roomName=${roomName}&token=${token}`;
        chatWS = new WebSocket(wsUrl);
        chatWS.onopen = () => {
            console.log('✅ Chat WebSocket connected (real-time, no polling)');
        };
        chatWS.onmessage = async (event) => {
            try {
                const messageObj = JSON.parse(event.data);
                await decryptTheMessage(messageObj.message);   
            } catch (e) {
                console.error('Error processing WS message:', e);
            }
        };
        chatWS.onclose = () => {
            console.warn('WebSocket closed. Reconnecting in 2s...');
            setTimeout(connectChatWebSocket, 2000);
        };
        chatWS.onerror = (err) => console.error('WebSocket error:', err);
    }


    document.getElementById("sendMsgBtn").addEventListener("click", () => { encryptTheMessage("msg", document.getElementById("messageInput").value) })
    document.getElementById("destroyChatBtn").addEventListener("click", deleteRoom)
    document.getElementById("newWindowBtn").addEventListener("click", openNewWindow)


    function openNewWindow() {
        const url = location.href;
        window.open(url, '_blank');
    }




    async function hostSendsMessage(base64EncryptedMsg) {
        try {
            const response = await fetch('http://localhost:3001/api/hostSendsMessage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    roomName,
                    hostToken,
                    message: base64EncryptedMsg
                })
            });
            if (response.status == "403") {
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
        try {
            const response = await fetch('http://localhost:3001/api/joinerSendsMessage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    roomName,
                    joinerToken,
                    message: base64EncryptedMsg
                })
            });
            if (response.status == "403") {
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
            false,
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
                    showFile(lastSentFileInfo.bytes, lastSentFileInfo.ext, "me");
                }
                if (msgOrFileOrCall === "msg") {
                    let message = document.getElementById("messageInput").value;
                    showMsg(message, "me");
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

            // === DETECT MESSAGE TYPE ===
            const first3 = new TextDecoder("utf-8", { fatal: false }).decode(msgBytes.slice(0, 3));
            if (/^\d{3}$/.test(first3) && first3 !== "000") {
                // Text message path
                const paddedMsg = new TextDecoder().decode(msgBytes);
                const realLen = parseInt(first3, 10);
                if (realLen < 0 || realLen > msgBytes.byteLength - 3) throw new Error("Invalid message length");
                const realMessage = paddedMsg.slice(3, 3 + realLen);
                showMsg(realMessage, "partner");
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
                showFile(fileBytes, safeExt || "bin", "partner");
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
        const safeExt = (ext || 'bin')
            .toString()
            .replace(/[^a-zA-Z0-9]/g, '')
            .slice(0, 4) || 'bin';
        const mimeMap = {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'webp': 'image/webp',
            'pdf': 'application/pdf'
        };
        const mimeType = mimeMap[safeExt.toLowerCase()] || 'application/octet-stream';
        const blobData = new Uint8Array(fileBytes);
        const blob = new Blob([blobData], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const li = document.createElement('li');
        if (mimeType.startsWith('image/')) {
            const a = document.createElement('a');
            a.href = url;
            a.download = `image.${safeExt}`;
            const img = document.createElement('img');
            img.src = url;
            img.alt = "Sent image";
            img.style.maxWidth = "80%";
            img.style.borderRadius = "8px";
            img.style.margin = "5px 0";
            img.style.cursor = "pointer";
            a.appendChild(img);
            li.appendChild(a);
        } else {
            const a = document.createElement('a');
            a.href = url;
            a.download = `file.${safeExt}`;
            a.style.color = "blue";
            a.style.textDecoration = "underline";
            a.textContent = `📎 Download ${safeExt.toUpperCase()}`;

            li.appendChild(a);
        }
        if (user === "partner") {
            li.style.color = "red";
            li.style.textShadow = "1px 1px white";
        } else if (user === "me") {
            li.style.color = "green";
            li.style.textShadow = "1px 1px white";
        }
        ul.appendChild(li);
    }



    // showMsg — minimal changes: normalize styling in one place
    function showMsg(message, user) {
        const ul = document.getElementById('ulChat');
        const li = document.createElement('li');
        li.textContent = message;
        li.style.fontSize = "larger";
        if (user == "partner") {
            li.style.color = "red"
            li.style.textShadow = "1px 1px white"
            ul.appendChild(li);
        }
        else if (user == "me") {
            li.style.color = "green"
            li.style.textShadow = "1px 1px white"
            ul.appendChild(li);
        }
        document.getElementById("messageInput").value = ""
    }


    async function deleteRoom() {
        let token
        if (userName == "host") {
            token = hostToken
        } else if (userName == "joiner") {
            token = joinerToken
        }
        try {
            const res = await fetch('http://localhost:3001/api/deleteRoom', {
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