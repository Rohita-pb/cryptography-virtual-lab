/* =========================================================
   DOUBLE DES & TRIPLE DES
   Interactive Virtual Cryptography Lab
   ========================================================= */


/* =========================================================
   HELPER FUNCTIONS
   ========================================================= */


/*
   Convert a hexadecimal key into a CryptoJS WordArray.

   DES uses an 8-byte key.

   8 bytes = 16 hexadecimal characters.
*/
function hexKey(hex) {

    return CryptoJS.enc.Hex.parse(hex.toUpperCase());

}


/*
   Validate a DES key.
*/
function isValidKey(key) {

    return /^[0-9A-Fa-f]{16}$/.test(key);

}


/*
   Display an error message.
*/
function showError(elementId, message) {

    const element = document.getElementById(elementId);

    element.textContent = message;

    element.classList.add("show");

}


/*
   Clear an error message.
*/
function clearError(elementId) {

    const element = document.getElementById(elementId);

    element.textContent = "";

    element.classList.remove("show");

}


/*
   Convert a CryptoJS WordArray into hexadecimal text.
*/
function wordArrayToHex(wordArray) {

    return CryptoJS.enc.Hex.stringify(wordArray).toUpperCase();

}


/* =========================================================
   DOUBLE DES
   ========================================================= */


/*
   DOUBLE DES ENCRYPTION

   C = E_K2( E_K1( M ) )

   Padding is applied once before the first encryption
   and is not applied again at the second stage.
*/
function doubleEncrypt() {

    clearError("doubleError");

    const message =
        document.getElementById("doubleMessage").value;

    const key1 =
        document.getElementById("doubleKey1").value.trim();

    const key2 =
        document.getElementById("doubleKey2").value.trim();


    /* Validation */

    if (message.length === 0) {

        showError(
            "doubleError",
            "Please enter a message."
        );

        return;
    }


    if (!isValidKey(key1)) {

        showError(
            "doubleError",
            "Key 1 must contain exactly 16 hexadecimal characters."
        );

        return;
    }


    if (!isValidKey(key2)) {

        showError(
            "doubleError",
            "Key 2 must contain exactly 16 hexadecimal characters."
        );

        return;
    }


    try {

        /*
           Convert plaintext into CryptoJS WordArray.
        */
        const plaintext =
            CryptoJS.enc.Utf8.parse(message);


        /*
           Pad plaintext once with PKCS7 before any encryption.
        */
        const paddedPlaintext = plaintext.clone();

        CryptoJS.pad.Pkcs7.pad(paddedPlaintext, 2);
        /* blockSize = 2 words = 8 bytes for DES */


        /*
           Stage 1:
           DES encryption using K1 (no padding — already padded)
        */
        const intermediate =
            CryptoJS.DES.encrypt(
                paddedPlaintext,
                hexKey(key1),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            ).ciphertext;


        /*
           Stage 2:
           DES encryption using K2 (no padding)
        */
        const ciphertext =
            CryptoJS.DES.encrypt(
                intermediate,
                hexKey(key2),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            ).ciphertext;


        /* Display */

        document.getElementById(
            "doublePlainDisplay"
        ).textContent = message;


        document.getElementById(
            "doubleIntermediate"
        ).textContent = wordArrayToHex(intermediate);


        document.getElementById(
            "doubleCipherDisplay"
        ).textContent = wordArrayToHex(ciphertext);


        document.getElementById(
            "doubleEncryptionResult"
        ).classList.remove("hidden");


        /*
           Store ciphertext for decryption.
        */
        window.doubleCiphertext = ciphertext;


        /*
           Store keys for decryption.
        */
        window.doubleKey1 = key1;
        window.doubleKey2 = key2;


    }
    catch (error) {

        console.error(error);

        showError(
            "doubleError",
            "Encryption failed. Please check your input."
        );

    }

}


/*
   DOUBLE DES DECRYPTION

   M = D_K1( D_K2( C ) )

   Unpadding is applied once after the final decryption.
*/
function doubleDecrypt() {

    clearError("doubleError");


    /*
       If encryption has already been performed,
       use its ciphertext.
    */
    let ciphertext = window.doubleCiphertext;


    const key1 =
        document.getElementById("doubleKey1").value.trim();

    const key2 =
        document.getElementById("doubleKey2").value.trim();


    if (!isValidKey(key1)) {

        showError(
            "doubleError",
            "Key 1 must contain exactly 16 hexadecimal characters."
        );

        return;
    }


    if (!isValidKey(key2)) {

        showError(
            "doubleError",
            "Key 2 must contain exactly 16 hexadecimal characters."
        );

        return;
    }


    if (!ciphertext) {

        showError(
            "doubleError",
            "Please click Encrypt first so that ciphertext is available for decryption."
        );

        return;
    }


    try {

        /*
           Stage 1:
           DES Decrypt using K2 (no unpadding).
        */
        const intermediate =
            CryptoJS.DES.decrypt(
                { ciphertext: ciphertext },
                hexKey(key2),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            );


        /*
           Stage 2:
           DES Decrypt using K1 (no unpadding).
        */
        const paddedPlaintext =
            CryptoJS.DES.decrypt(
                { ciphertext: intermediate },
                hexKey(key1),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            );


        /*
           Remove PKCS7 padding once.
        */
        CryptoJS.pad.Pkcs7.unpad(paddedPlaintext);


        const message =
            CryptoJS.enc.Utf8.stringify(paddedPlaintext);


        document.getElementById(
            "doubleDecryptCipher"
        ).textContent = wordArrayToHex(ciphertext);


        document.getElementById(
            "doubleDecryptIntermediate"
        ).textContent = wordArrayToHex(intermediate);


        document.getElementById(
            "doubleDecryptedMessage"
        ).textContent = message;


        document.getElementById(
            "doubleDecryptionResult"
        ).classList.remove("hidden");


    }
    catch (error) {

        console.error(error);

        showError(
            "doubleError",
            "Decryption failed. Please encrypt a message first."
        );

    }

}


/*
   Clear Double DES.
*/
function clearDoubleDES() {

    document.getElementById(
        "doubleMessage"
    ).value = "";

    document.getElementById(
        "doubleKey1"
    ).value = "";

    document.getElementById(
        "doubleKey2"
    ).value = "";


    document.getElementById(
        "doubleEncryptionResult"
    ).classList.add("hidden");


    document.getElementById(
        "doubleDecryptionResult"
    ).classList.add("hidden");


    clearError("doubleError");


    window.doubleCiphertext = null;

}


/* =========================================================
   TRIPLE DES MODE
   ========================================================= */


/*
   Return selected Triple DES mode.
*/
function getTripleMode() {

    const selected =
        document.querySelector(
            'input[name="tripleMode"]:checked'
        );

    return selected.value;

}


/*
   Change UI according to selected key count.
*/
function changeTripleMode() {

    const mode = getTripleMode();

    const key2Group =
        document.getElementById("tripleKey2Group");

    const key3Group =
        document.getElementById("tripleKey3Group");

    const description =
        document.getElementById("tripleModeDescription");


    /*
       1 KEY
    */

    if (mode === "1") {

        key2Group.classList.add("hidden");

        key3Group.classList.add("hidden");

        description.innerHTML =
            "<strong>1-Key Triple DES:</strong> " +
            "K1 → K1 → K1 using EDE.";

    }


    /*
       2 KEYS
    */

    else if (mode === "2") {

        key2Group.classList.remove("hidden");

        key3Group.classList.add("hidden");

        description.innerHTML =
            "<strong>2-Key Triple DES:</strong> " +
            "K1 → K2 → K1 using EDE.";

    }


    /*
       3 KEYS
    */

    else {

        key2Group.classList.remove("hidden");

        key3Group.classList.remove("hidden");

        description.innerHTML =
            "<strong>3-Key Triple DES:</strong> " +
            "K1 → K2 → K3 using EDE.";

    }


    /*
       Clear previous results when mode changes.
    */
    document.getElementById(
        "tripleEncryptionResult"
    ).classList.add("hidden");


    document.getElementById(
        "tripleDecryptionResult"
    ).classList.add("hidden");


    clearError("tripleError");

}


/* =========================================================
   TRIPLE DES KEY PREPARATION
   ========================================================= */


/*
   Return the three keys required for Triple DES.
*/
function prepareTripleKeys() {

    const mode = getTripleMode();


    const key1 =
        document.getElementById(
            "tripleKey1"
        ).value.trim().toUpperCase();


    let key2 = key1;

    let key3 = key1;


    /*
       2-key Triple DES:
       K1 K2 K1
    */

    if (mode === "2") {

        key2 =
            document.getElementById(
                "tripleKey2"
            ).value.trim().toUpperCase();

        key3 = key1;

    }


    /*
       3-key Triple DES:
       K1 K2 K3
    */

    if (mode === "3") {

        key2 =
            document.getElementById(
                "tripleKey2"
            ).value.trim().toUpperCase();

        key3 =
            document.getElementById(
                "tripleKey3"
            ).value.trim().toUpperCase();

    }


    return {
        key1: key1,
        key2: key2,
        key3: key3
    };

}


/* =========================================================
   TRIPLE DES ENCRYPTION
   ========================================================= */

function tripleEncrypt() {

    clearError("tripleError");

    const message =
        document.getElementById("tripleMessage").value;

    const mode = getTripleMode();

    const keys = prepareTripleKeys();

    if (message.length === 0) {

        showError(
            "tripleError",
            "Please enter a message."
        );

        return;
    }

    if (!isValidKey(keys.key1)) {

        showError(
            "tripleError",
            "Key 1 must contain exactly 16 hexadecimal characters."
        );

        return;
    }

    if (
        (mode === "2" || mode === "3") &&
        !isValidKey(keys.key2)
    ) {

        showError(
            "tripleError",
            "Key 2 must contain exactly 16 hexadecimal characters."
        );

        return;
    }

    if (
        mode === "3" &&
        !isValidKey(keys.key3)
    ) {

        showError(
            "tripleError",
            "Key 3 must contain exactly 16 hexadecimal characters."
        );

        return;
    }

    try {

        /*
           Convert message into WordArray.
        */
        const plaintext =
            CryptoJS.enc.Utf8.parse(message);


        /*
           Pad plaintext once with PKCS7.
        */
        const data = plaintext.clone();

        CryptoJS.pad.Pkcs7.pad(data, 2);
        /* blockSize = 2 words = 8 bytes for DES */


        /*
           Stage 1:
           E(K1)
        */
        const stage1 =
            CryptoJS.DES.encrypt(
                data,
                hexKey(keys.key1),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            ).ciphertext;


        /*
           Stage 2:
           D(K2)
        */
        const stage2 =
            CryptoJS.DES.decrypt(
                {
                    ciphertext: stage1
                },
                hexKey(keys.key2),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            );


        /*
           Stage 3:
           E(K3)
        */
        const stage3 =
            CryptoJS.DES.encrypt(
                stage2,
                hexKey(keys.key3),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            ).ciphertext;


        document.getElementById(
            "triplePlainDisplay"
        ).textContent = message;


        document.getElementById(
            "tripleStep1"
        ).textContent =
            wordArrayToHex(stage1);


        document.getElementById(
            "tripleStep2"
        ).textContent =
            wordArrayToHex(stage2);


        document.getElementById(
            "tripleCipherDisplay"
        ).textContent =
            wordArrayToHex(stage3);


        document.getElementById(
            "tripleEncryptionResult"
        ).classList.remove("hidden");


        window.tripleCiphertext = stage3;

        window.tripleKeys = keys;

    }

    catch (error) {

        console.error(error);

        showError(
            "tripleError",
            "Triple DES encryption failed."
        );

    }

}


/* =========================================================
   TRIPLE DES DECRYPTION
   ========================================================= */

function tripleDecrypt() {

    clearError("tripleError");

    const mode = getTripleMode();

    const keys = prepareTripleKeys();

    if (!isValidKey(keys.key1)) {

        showError(
            "tripleError",
            "Key 1 must contain exactly 16 hexadecimal characters."
        );

        return;
    }

    if (
        (mode === "2" || mode === "3") &&
        !isValidKey(keys.key2)
    ) {

        showError(
            "tripleError",
            "Key 2 must contain exactly 16 hexadecimal characters."
        );

        return;
    }

    if (
        mode === "3" &&
        !isValidKey(keys.key3)
    ) {

        showError(
            "tripleError",
            "Key 3 must contain exactly 16 hexadecimal characters."
        );

        return;
    }

    if (!window.tripleCiphertext) {

        showError(
            "tripleError",
            "Please click Encrypt first so that ciphertext is available."
        );

        return;
    }

    try {

        const ciphertext =
            window.tripleCiphertext;


        /*
           Stage 1:
           D(K3)
        */
        const stage1 =
            CryptoJS.DES.decrypt(
                {
                    ciphertext: ciphertext
                },
                hexKey(keys.key3),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            );


        /*
           Stage 2:
           E(K2)
        */
        const stage2 =
            CryptoJS.DES.encrypt(
                stage1,
                hexKey(keys.key2),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            ).ciphertext;


        /*
           Stage 3:
           D(K1)
        */
        const paddedPlaintext =
            CryptoJS.DES.decrypt(
                {
                    ciphertext: stage2
                },
                hexKey(keys.key1),
                {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            );


        /*
           Remove PKCS7 padding.
        */
        CryptoJS.pad.Pkcs7.unpad(paddedPlaintext);


        const message =
            CryptoJS.enc.Utf8.stringify(
                paddedPlaintext
            );


        document.getElementById(
            "tripleDecryptCipher"
        ).textContent =
            wordArrayToHex(ciphertext);


        document.getElementById(
            "tripleDecryptStep1"
        ).textContent =
            wordArrayToHex(stage1);


        document.getElementById(
            "tripleDecryptStep2"
        ).textContent =
            wordArrayToHex(stage2);


        document.getElementById(
            "tripleDecryptedMessage"
        ).textContent =
            message;


        document.getElementById(
            "tripleDecryptionResult"
        ).classList.remove("hidden");

    }

    catch (error) {

        console.error(error);

        showError(
            "tripleError",
            "Triple DES decryption failed. Please encrypt again and check the keys."
        );

    }

}


/* =========================================================
   CLEAR TRIPLE DES
   ========================================================= */

function clearTripleDES() {

    document.getElementById(
        "tripleMessage"
    ).value = "";


    document.getElementById(
        "tripleKey1"
    ).value = "";


    document.getElementById(
        "tripleKey2"
    ).value = "";


    document.getElementById(
        "tripleKey3"
    ).value = "";


    document.getElementById(
        "tripleEncryptionResult"
    ).classList.add("hidden");


    document.getElementById(
        "tripleDecryptionResult"
    ).classList.add("hidden");


    clearError("tripleError");


    window.tripleCiphertext = null;

}


/* =========================================================
   QUIZ
   ========================================================= */

function checkQuiz() {

    const answers = {

        q1: "c",

        q2: "b",

        q3: "b",

        q4: "b",

        q5: "a"

    };


    let score = 0;


    Object.keys(answers).forEach(
        function(question) {

            const selected =
                document.querySelector(
                    `input[name="${question}"]:checked`
                );


            if (
                selected &&
                selected.value === answers[question]
            ) {

                score++;

            }

        }
    );


    const result =
        document.getElementById(
            "quizResult"
        );


    result.textContent =
        `You scored ${score} out of 5.`;


    if (score === 5) {

        result.style.color = "#315e31";

        result.textContent +=
            " Excellent! All answers are correct.";

    }

    else if (score >= 3) {

        result.style.color = "#8d6351";

        result.textContent +=
            " Good attempt. Review the theory for the remaining questions.";

    }

    else {

        result.style.color = "#a33a32";

        result.textContent +=
            " Please review the theory and try again.";

    }

}


/* =========================================================
   SHARE
   ========================================================= */

function shareExperiment() {

    if (
        navigator.share
    ) {

        navigator.share({

            title:
                "Double DES & Triple DES",

            text:
                "Interactive Cryptography Virtual Lab - Double DES & Triple DES",

            url:
                window.location.href

        });

    }

    else {

        navigator.clipboard.writeText(
            window.location.href
        );

        alert(
            "Experiment link copied to clipboard."
        );

    }

}


/* =========================================================
   INITIALIZATION
   ========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    function() {

        changeTripleMode();

    }
);