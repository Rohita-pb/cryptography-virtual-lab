/* =========================================================
   DOUBLE DES & TRIPLE DES VIRTUAL LAB
   Interactive Cryptography Engine, S-Box & Quiz Module
   ========================================================= */


/* =========================================================
   1. AUTHENTIC DES DATA TABLES
   ========================================================= */

/*
   Authentic DES S-Box 1 (S1) Matrix
   Specification: NIST FIPS PUB 46-3
   4 Rows x 16 Columns (Entries 0 to 15)
*/
const S1_TABLE = [
    [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7], // Row 0 (00_2)
    [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8], // Row 1 (01_2)
    [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0], // Row 2 (10_2)
    [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]  // Row 3 (11_2)
];


/* =========================================================
   2. CORE CRYPTOGRAPHIC HELPER FUNCTIONS
   ========================================================= */

/* Convert a hexadecimal key string into a CryptoJS WordArray (8 bytes = 16 hex chars) */
function hexKey(hex) {
    return CryptoJS.enc.Hex.parse(hex.toUpperCase());
}

/* Validate that a key contains exactly 16 hexadecimal characters (64 bits) */
function isValidKey(key) {
    return /^[0-9A-Fa-f]{16}$/.test(key);
}

/* Display error message in designated element */
function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.classList.add("show");
    }
}

/* Clear error message from designated element */
function clearError(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = "";
        element.classList.remove("show");
    }
}

/* Convert a CryptoJS WordArray into uppercase hexadecimal string */
function wordArrayToHex(wordArray) {
    return CryptoJS.enc.Hex.stringify(wordArray).toUpperCase();
}


/* =========================================================
   3. DOUBLE DES IMPLEMENTATION
   ========================================================= */

/*
   Double DES Encryption:
   C = E(K2, E(K1, P))
*/
function doubleEncrypt() {
    clearError("doubleError");

    const message = document.getElementById("doubleMessage").value;
    const key1 = document.getElementById("doubleKey1").value.trim();
    const key2 = document.getElementById("doubleKey2").value.trim();

    if (message.length === 0) {
        showError("doubleError", "Please enter a message to encrypt.");
        return;
    }

    if (!isValidKey(key1)) {
        showError("doubleError", "Key 1 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if (!isValidKey(key2)) {
        showError("doubleError", "Key 2 must contain exactly 16 hexadecimal characters.");
        return;
    }

    try {
        const plaintext = CryptoJS.enc.Utf8.parse(message);
        const paddedPlaintext = plaintext.clone();
        CryptoJS.pad.Pkcs7.pad(paddedPlaintext, 2); // Block size 8 bytes

        // Stage 1: DES Encryption using K1
        const intermediate = CryptoJS.DES.encrypt(
            paddedPlaintext,
            hexKey(key1),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        ).ciphertext;

        // Stage 2: DES Encryption using K2
        const ciphertext = CryptoJS.DES.encrypt(
            intermediate,
            hexKey(key2),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        ).ciphertext;

        // Display results
        document.getElementById("doublePlainDisplay").textContent = message;
        document.getElementById("doubleIntermediate").textContent = wordArrayToHex(intermediate);
        document.getElementById("doubleCipherDisplay").textContent = wordArrayToHex(ciphertext);
        document.getElementById("doubleEncryptionResult").classList.remove("hidden");

        // Cache for decryption
        window.doubleCiphertext = ciphertext;
        window.doubleKey1 = key1;
        window.doubleKey2 = key2;
    } catch (error) {
        console.error(error);
        showError("doubleError", "Double DES encryption failed. Please check inputs.");
    }
}

/*
   Double DES Decryption:
   P = D(K1, D(K2, C))
*/
function doubleDecrypt() {
    clearError("doubleError");

    let ciphertext = window.doubleCiphertext;
    const key1 = document.getElementById("doubleKey1").value.trim();
    const key2 = document.getElementById("doubleKey2").value.trim();

    if (!isValidKey(key1)) {
        showError("doubleError", "Key 1 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if (!isValidKey(key2)) {
        showError("doubleError", "Key 2 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if (!ciphertext) {
        showError("doubleError", "Please click Encrypt first so that ciphertext is available for decryption.");
        return;
    }

    try {
        // Stage 1: DES Decrypt using K2
        const intermediate = CryptoJS.DES.decrypt(
            { ciphertext: ciphertext },
            hexKey(key2),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        );

        // Stage 2: DES Decrypt using K1
        const paddedPlaintext = CryptoJS.DES.decrypt(
            { ciphertext: intermediate },
            hexKey(key1),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        );

        CryptoJS.pad.Pkcs7.unpad(paddedPlaintext);
        const message = CryptoJS.enc.Utf8.stringify(paddedPlaintext);

        document.getElementById("doubleDecryptCipher").textContent = wordArrayToHex(ciphertext);
        document.getElementById("doubleDecryptIntermediate").textContent = wordArrayToHex(intermediate);
        document.getElementById("doubleDecryptedMessage").textContent = message;
        document.getElementById("doubleDecryptionResult").classList.remove("hidden");
    } catch (error) {
        console.error(error);
        showError("doubleError", "Decryption failed. Please verify keys and encrypt first.");
    }
}

function clearDoubleDES() {
    document.getElementById("doubleMessage").value = "";
    document.getElementById("doubleKey1").value = "";
    document.getElementById("doubleKey2").value = "";
    document.getElementById("doubleEncryptionResult").classList.add("hidden");
    document.getElementById("doubleDecryptionResult").classList.add("hidden");
    clearError("doubleError");
    window.doubleCiphertext = null;
}


/* =========================================================
   4. TRIPLE DES IMPLEMENTATION (1-Key, 2-Key, 3-Key EDE)
   ========================================================= */

function getTripleMode() {
    const selected = document.querySelector('input[name="tripleMode"]:checked');
    return selected ? selected.value : "1";
}

function changeTripleMode() {
    const mode = getTripleMode();
    const key2Group = document.getElementById("tripleKey2Group");
    const key3Group = document.getElementById("tripleKey3Group");
    const description = document.getElementById("tripleModeDescription");

    if (mode === "1") {
        key2Group.classList.add("hidden");
        key3Group.classList.add("hidden");
        description.innerHTML = "<strong>1-Key Triple DES:</strong> K1 → K1 → K1 using EDE (Equivalent to single DES).";
    } else if (mode === "2") {
        key2Group.classList.remove("hidden");
        key3Group.classList.add("hidden");
        description.innerHTML = "<strong>2-Key Triple DES:</strong> K1 → K2 → K1 using EDE (112-bit effective key length).";
    } else {
        key2Group.classList.remove("hidden");
        key3Group.classList.remove("hidden");
        description.innerHTML = "<strong>3-Key Triple DES:</strong> K1 → K2 → K3 using EDE (168-bit key length, standard).";
    }

    document.getElementById("tripleEncryptionResult").classList.add("hidden");
    document.getElementById("tripleDecryptionResult").classList.add("hidden");
    clearError("tripleError");
}

function prepareTripleKeys() {
    const mode = getTripleMode();
    const key1 = document.getElementById("tripleKey1").value.trim().toUpperCase();
    let key2 = key1;
    let key3 = key1;

    if (mode === "2") {
        key2 = document.getElementById("tripleKey2").value.trim().toUpperCase();
        key3 = key1;
    } else if (mode === "3") {
        key2 = document.getElementById("tripleKey2").value.trim().toUpperCase();
        key3 = document.getElementById("tripleKey3").value.trim().toUpperCase();
    }

    return { key1, key2, key3 };
}

/*
   Triple DES Encryption:
   C = E(K3, D(K2, E(K1, P)))
*/
function tripleEncrypt() {
    clearError("tripleError");

    const message = document.getElementById("tripleMessage").value;
    const mode = getTripleMode();
    const keys = prepareTripleKeys();

    if (message.length === 0) {
        showError("tripleError", "Please enter a message.");
        return;
    }

    if (!isValidKey(keys.key1)) {
        showError("tripleError", "Key 1 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if ((mode === "2" || mode === "3") && !isValidKey(keys.key2)) {
        showError("tripleError", "Key 2 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if (mode === "3" && !isValidKey(keys.key3)) {
        showError("tripleError", "Key 3 must contain exactly 16 hexadecimal characters.");
        return;
    }

    try {
        const plaintext = CryptoJS.enc.Utf8.parse(message);
        const data = plaintext.clone();
        CryptoJS.pad.Pkcs7.pad(data, 2);

        // Stage 1: E(K1)
        const stage1 = CryptoJS.DES.encrypt(
            data,
            hexKey(keys.key1),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        ).ciphertext;

        // Stage 2: D(K2)
        const stage2 = CryptoJS.DES.decrypt(
            { ciphertext: stage1 },
            hexKey(keys.key2),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        );

        // Stage 3: E(K3)
        const stage3 = CryptoJS.DES.encrypt(
            stage2,
            hexKey(keys.key3),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        ).ciphertext;

        document.getElementById("triplePlainDisplay").textContent = message;
        document.getElementById("tripleStep1").textContent = wordArrayToHex(stage1);
        document.getElementById("tripleStep2").textContent = wordArrayToHex(stage2);
        document.getElementById("tripleCipherDisplay").textContent = wordArrayToHex(stage3);
        document.getElementById("tripleEncryptionResult").classList.remove("hidden");

        window.tripleCiphertext = stage3;
        window.tripleKeys = keys;
    } catch (error) {
        console.error(error);
        showError("tripleError", "Triple DES encryption failed. Please verify inputs.");
    }
}

/*
   Triple DES Decryption:
   P = D(K1, E(K2, D(K3, C)))
*/
function tripleDecrypt() {
    clearError("tripleError");

    const mode = getTripleMode();
    const keys = prepareTripleKeys();

    if (!isValidKey(keys.key1)) {
        showError("tripleError", "Key 1 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if ((mode === "2" || mode === "3") && !isValidKey(keys.key2)) {
        showError("tripleError", "Key 2 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if (mode === "3" && !isValidKey(keys.key3)) {
        showError("tripleError", "Key 3 must contain exactly 16 hexadecimal characters.");
        return;
    }

    if (!window.tripleCiphertext) {
        showError("tripleError", "Please click Encrypt first so that ciphertext is available.");
        return;
    }

    try {
        const ciphertext = window.tripleCiphertext;

        // Stage 1: D(K3)
        const stage1 = CryptoJS.DES.decrypt(
            { ciphertext: ciphertext },
            hexKey(keys.key3),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        );

        // Stage 2: E(K2)
        const stage2 = CryptoJS.DES.encrypt(
            stage1,
            hexKey(keys.key2),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        ).ciphertext;

        // Stage 3: D(K1)
        const paddedPlaintext = CryptoJS.DES.decrypt(
            { ciphertext: stage2 },
            hexKey(keys.key1),
            { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
        );

        CryptoJS.pad.Pkcs7.unpad(paddedPlaintext);
        const message = CryptoJS.enc.Utf8.stringify(paddedPlaintext);

        document.getElementById("tripleDecryptCipher").textContent = wordArrayToHex(ciphertext);
        document.getElementById("tripleDecryptStep1").textContent = wordArrayToHex(stage1);
        document.getElementById("tripleDecryptStep2").textContent = wordArrayToHex(stage2);
        document.getElementById("tripleDecryptedMessage").textContent = message;
        document.getElementById("tripleDecryptionResult").classList.remove("hidden");
    } catch (error) {
        console.error(error);
        showError("tripleError", "Triple DES decryption failed. Please verify keys and encrypt first.");
    }
}

function clearTripleDES() {
    document.getElementById("tripleMessage").value = "";
    document.getElementById("tripleKey1").value = "";
    document.getElementById("tripleKey2").value = "";
    document.getElementById("tripleKey3").value = "";
    document.getElementById("tripleEncryptionResult").classList.add("hidden");
    document.getElementById("tripleDecryptionResult").classList.add("hidden");
    clearError("tripleError");
    window.tripleCiphertext = null;
}


/* =========================================================
   5. S-BOX (S1) INTERACTIVE LOGIC (Requirement 5)
   ========================================================= */

function calculateSBox() {
    clearError("sboxError");
    const inputField = document.getElementById("sboxInput");
    const inputVal = inputField.value.trim();

    // Validation: Exactly 6 binary characters
    if (inputVal.length === 0) {
        showError("sboxError", "Please enter a 6-bit binary value (e.g., 011011).");
        return;
    }

    if (inputVal.length !== 6) {
        showError("sboxError", `Input must be exactly 6 binary digits. Current length is ${inputVal.length}.`);
        return;
    }

    if (!/^[01]{6}$/.test(inputVal)) {
        showError("sboxError", "Invalid binary input! Only '0' and '1' characters are permitted.");
        return;
    }

    // Extraction: Outer bits determine Row, Middle 4 bits determine Column
    const b1 = inputVal[0];
    const b2 = inputVal[1];
    const b3 = inputVal[2];
    const b4 = inputVal[3];
    const b5 = inputVal[4];
    const b6 = inputVal[5];

    const rowBinary = b1 + b6;
    const rowDecimal = parseInt(rowBinary, 2); // 0, 1, 2, or 3

    const colBinary = b2 + b3 + b4 + b5;
    const colDecimal = parseInt(colBinary, 2); // 0 to 15

    // Lookup authentic S1 value
    const outputDecimal = S1_TABLE[rowDecimal][colDecimal];
    const outputBinary = outputDecimal.toString(2).padStart(4, "0");

    // Display Step 1: Bits breakdown
    const bitsContainer = document.getElementById("sboxBitsDisplay");
    bitsContainer.innerHTML = `
        <div class="bit-pill bit-row" title="Bit 1 (Outer - Row)">${b1}<small>b1</small></div>
        <div class="bit-pill bit-col" title="Bit 2 (Middle - Col)">${b2}<small>b2</small></div>
        <div class="bit-pill bit-col" title="Bit 3 (Middle - Col)">${b3}<small>b3</small></div>
        <div class="bit-pill bit-col" title="Bit 4 (Middle - Col)">${b4}<small>b4</small></div>
        <div class="bit-pill bit-col" title="Bit 5 (Middle - Col)">${b5}<small>b5</small></div>
        <div class="bit-pill bit-row" title="Bit 6 (Outer - Row)">${b6}<small>b6</small></div>
    `;

    // Step 2 & 3: Row and Column
    document.getElementById("sboxRowBinary").innerHTML = `(b<sub>1</sub>b<sub>6</sub>) = ${rowBinary}<sub>2</sub>`;
    document.getElementById("sboxRowDecimal").textContent = `Row ${rowDecimal}`;

    document.getElementById("sboxColBinary").innerHTML = `(b<sub>2</sub>b<sub>3</sub>b<sub>4</sub>b<sub>5</sub>) = ${colBinary}<sub>2</sub>`;
    document.getElementById("sboxColDecimal").textContent = `Column ${colDecimal}`;

    // Step 4: Final Lookup & 4-bit output
    document.getElementById("sboxResRow").textContent = rowDecimal;
    document.getElementById("sboxResCol").textContent = colDecimal;
    document.getElementById("sboxTableValue").textContent = outputDecimal;
    document.getElementById("sboxOutputBits").textContent = outputBinary;

    // Highlight row, column, and cell in authentic table
    highlightSBoxTable(rowDecimal, colDecimal);
}

function highlightSBoxTable(row, col) {
    // Clear all previous highlight classes
    document.querySelectorAll(".sbox-lookup-table tr").forEach(tr => {
        tr.classList.remove("sbox-row-highlight");
    });

    document.querySelectorAll(".sbox-lookup-table td, .sbox-lookup-table th").forEach(cell => {
        cell.classList.remove("sbox-col-highlight");
        cell.classList.remove("sbox-col-active-th");
        cell.classList.remove("sbox-cell-highlight");
    });

    // Highlight row
    const targetRow = document.getElementById(`sbox-tr-${row}`);
    if (targetRow) {
        targetRow.classList.add("sbox-row-highlight");
    }

    // Highlight column in table header
    const tableHeaders = document.querySelectorAll(".sbox-lookup-table thead th");
    if (tableHeaders[col + 1]) { // +1 to skip row-corner
        tableHeaders[col + 1].classList.add("sbox-col-active-th");
    }

    // Highlight column cells across all rows
    document.querySelectorAll(".sbox-lookup-table tbody tr").forEach(tr => {
        const cells = tr.querySelectorAll("td");
        if (cells[col]) {
            cells[col].classList.add("sbox-col-highlight");
        }
    });

    // Highlight intersection cell
    if (targetRow) {
        const cells = targetRow.querySelectorAll("td");
        if (cells[col]) {
            cells[col].classList.add("sbox-cell-highlight");
        }
    }
}

function setSBoxInput(val) {
    document.getElementById("sboxInput").value = val;
    calculateSBox();
}

function resetSBox() {
    document.getElementById("sboxInput").value = "011011";
    clearError("sboxError");
    calculateSBox();
}


/* =========================================================
   6. ADVANCED ENGINEERING QUIZ (10 Questions - Requirement 6)
   ========================================================= */

const QUIZ_QUESTIONS = [
    {
        id: "q1",
        title: "1. Order of Operations in Triple DES (EDE Architecture)",
        prompt: "Why is the second stage of standard Triple DES defined as Decryption (D) rather than Encryption (E)?",
        options: [
            "It guarantees backward compatibility with single DES when K1 = K2 = K3, because E(K1, D(K1, E(K1, P))) = E(K1, P).",
            "It doubles the effective key entropy from 112 bits to 224 bits compared to triple encryption.",
            "Decryption is mathematically non-linear, thereby providing Shannon diffusion across key schedules.",
            "It completely eliminates the vulnerability of the outer rounds to differential cryptanalysis."
        ],
        correct: 0,
        explanation: "In standard Triple DES EDE, if all three keys are identical (K1 = K2 = K3), the middle decryption stage D(K1) immediately cancels out the first encryption stage E(K1), yielding single DES: E(K1, P). This backward compatibility with legacy single DES hardware was a foundational design requirement."
    },
    {
        id: "q2",
        title: "2. Identifying Triple DES Mathematical Inversion",
        prompt: "Given standard 3-Key Triple DES encryption C = E(K3, D(K2, E(K1, P))), which expression correctly represents the exact mathematical decryption operation to recover plaintext P?",
        options: [
            "P = D(K3, E(K2, D(K1, C)))",
            "P = D(K1, E(K2, D(K3, C)))",
            "P = E(K1, D(K2, E(K3, C)))",
            "P = D(K1, D(K2, D(K3, C)))"
        ],
        correct: 1,
        explanation: "To mathematically invert the nested function C = E(K3, D(K2, E(K1, P))), outer operations must be undone first: invert E(K3) with D(K3, C), then invert D(K2) with E(K2, ·), and finally invert E(K1) with D(K1, ·), yielding P = D(K1, E(K2, D(K3, C)))."
    },
    {
        id: "q3",
        title: "3. Impact of Permuting the Order of Keys",
        prompt: "If a sender encrypts plaintext using 3-Key Triple DES with key sequence (K1, K2, K3), but the receiver decrypts using key sequence permuted to (K3, K2, K1) in the standard decryption formula, what will occur?",
        options: [
            "The receiver will successfully recover P because block cipher round operations commute.",
            "The receiver will obtain pseudorandom garbage data because block cipher operations under different keys do not commute.",
            "The receiver will obtain the bitwise complement of the plaintext due to DES complementation properties.",
            "Decryption will succeed if and only if K1 ⊕ K2 ⊕ K3 = 0."
        ],
        correct: 0,
        explanation: "Decryption in Triple DES reverses the encryption stages: using the key sequence (K3, K2, K1) in reverse order successfully decrypts intermediate stages to recover the original plaintext P."
    },
    {
        id: "q4",
        title: "4. Understanding Triple DES Flowchart Intermediate Stages",
        prompt: "In the 3-Key Triple DES EDE flowchart, Stage 1 produces intermediate block X1 = E(K1, P). What exact operation transforms X1 into intermediate block X2 in Stage 2?",
        options: [
            "X2 = E(K2, X1) (DES Encryption using Key 2)",
            "X2 = D(K2, X1) (DES Decryption using Key 2)",
            "X2 = X1 ⊕ K2 (Bitwise XOR with Key 2)",
            "X2 = D(K1, X1) (DES Decryption using Key 1)"
        ],
        correct: 1,
        explanation: "In the standard Triple DES Encrypt–Decrypt–Encrypt (EDE) architecture, Stage 2 performs DES Decryption on the intermediate value X1 using Key 2, producing X2 = D(K2, X1)."
    },
    {
        id: "q5",
        title: "5. Calculating S-Box Addressing from a 6-Bit Input",
        prompt: "In the DES substitution stage, a 6-bit binary chunk '101100' enters S-box S1. What are the corresponding row and column indices (in decimal) used for table lookup?",
        options: [
            "Row 2, Column 6",
            "Row 2, Column 11",
            "Row 1, Column 6",
            "Row 3, Column 12"
        ],
        correct: 0,
        explanation: "In DES S-box addressing, the outer bits (b1 and b6) determine the row: '1' and '0' form binary '10'₂ = Row 2. The inner four bits (b2, b3, b4, b5) determine the column: '0110'₂ = (0·8 + 1·4 + 1·2 + 0·1) = Column 6."
    },
    {
        id: "q6",
        title: "6. Total S-Box Output",
        prompt: "During the substitution phase of a DES round, the 48-bit mixed data is divided into smaller blocks and fed into multiple S-boxes operating in parallel. How many S-boxes are there, and what is the total combined size of their output before it goes to the P-box?",
        options: [
            "8 S-boxes producing a combined 32-bit output.",
            "16 S-boxes producing a combined 64-bit output.",
            "4 S-boxes producing a combined 16-bit output.",
            "8 S-boxes producing a combined 48-bit output."
        ],
        correct: 0,
        explanation: "The 48-bit input is split into eight separate 6-bit chunks. Each of these chunks is processed by one of the 8 distinct S-boxes (S1 through S8). Since each S-box outputs 4 bits, the combined output of all 8 S-boxes is exactly 32 bits (8 × 4 = 32), which is then passed to the Permutation box (P-box)."
    },
    {
        id: "q7",
        title: "7. S-Box Row Permutation Property",
        prompt: "If you fix the outer two bits of the 6-bit input to a specific DES S-box (effectively locking it to a single row) and iterate through all 16 possible combinations of the inner four bits, what is guaranteed about the resulting 16 outputs?",
        options: [
            "The outputs will be a random distribution of 4-bit values, where some values may appear multiple times.",
            "The outputs will contain exactly the integers 0 through 15 with absolutely no duplicates.",
            "The outputs will always result in an even parity for each 4-bit block.",
            "The outputs will expand the data size to compensate for the initial compression."
        ],
        correct: 1,
        explanation: "A fundamental structural rule of the DES S-boxes is that each of the four rows within an S-box acts as a strict mathematical permutation of the integers 0 through 15. This means that for any given row, every possible 4-bit output appears exactly once. This design ensures that no two distinct 6-bit inputs can produce the same 4-bit output if they share the same outer bits."
    },
    {
        id: "q8",
        title: "8. Shannon's Cipher Principles: Substitution vs Permutation",
        prompt: "According to Claude Shannon's cipher design principles, what cryptographic roles do DES S-boxes and P-box permutations fulfill respectively?",
        options: [
            "S-boxes provide Confusion (non-linearity), while P-boxes provide Diffusion (spreading bit influence across rounds).",
            "S-boxes provide Diffusion, while P-boxes provide Authentication.",
            "Both S-boxes and P-boxes provide purely linear Confusion to resist exhaustive key search.",
            "S-boxes expand subkeys, while P-boxes perform non-linear substitution."
        ],
        correct: 0,
        explanation: "S-boxes are the ONLY non-linear elements in the DES algorithm, providing Shannon's property of Confusion (obscuring algebraic correlations between plaintext, key, and ciphertext). The Permutation (P-box) provides Diffusion by distributing the 4 output bits of each S-box across multiple different S-boxes in subsequent Feistel rounds."
    },
    {
        id: "q9",
        title: "9. Detecting Flaws in Cryptographic Implementation",
        prompt: "A developer implements a cipher as: C = E(K3, E(K2, D(K1, P))). What architectural flaw is present compared to standard Triple DES?",
        options: [
            "The sequence applies Decrypt-Encrypt-Encrypt (DEE) instead of the standard Encrypt-Decrypt-Encrypt (EDE) structure.",
            "DES blocks cannot be encrypted twice in succession without an intermediate permutation stage.",
            "The formula uses three keys instead of two keys.",
            "The formula is mathematically equivalent to EDE because symmetric ciphers are self-inverting."
        ],
        correct: 0,
        explanation: "Standard Triple DES is strictly an Encrypt–Decrypt–Encrypt (EDE) construction. The developer's implementation begins with Decryption under K1 and then performs two successive Encryptions under K2 and K3 (DEE mode), which violates the NIST standard and breaks compatibility."
    },
    {
        id: "q10",
        title: "10. Rationale: Why Not Triple Encryption (EEE)?",
        prompt: "Why did cryptographic standards adopt Encrypt–Decrypt–Encrypt (EDE) rather than simple triple encryption Encrypt–Encrypt–Encrypt (EEE)?",
        options: [
            "Because EEE is algebraically insecure and automatically collapses into a single 56-bit DES operation.",
            "Because EDE allows seamless backward compatibility: when K1 = K2, the system natively implements single DES with key K3 (or with K1 = K2 = K3 for 1-key mode).",
            "Because DES decryption requires significantly fewer clock cycles than encryption on hardware microcontrollers.",
            "Because triple encryption violates the Feistel round invariant."
        ],
        correct: 1,
        explanation: "The EDE construction was selected primarily for backward compatibility with legacy single DES hardware. Setting K1 = K2 causes the decryption stage to invert the first encryption: E(K1, D(K1, E(K3, P))) = E(K3, P), allowing a Triple DES chip to interoperate seamlessly with older single DES systems."
    }
];

let userAnswers = {};

function renderQuiz() {
    const container = document.getElementById("quizQuestionsContainer");
    if (!container) return;

    container.innerHTML = "";

    QUIZ_QUESTIONS.forEach((q, qIndex) => {
        const card = document.createElement("div");
        card.className = "quiz-card";
        card.id = `quiz-card-${q.id}`;

        let optionsHtml = "";
        q.options.forEach((opt, optIndex) => {
            optionsHtml += `
                <label class="quiz-option" id="label-${q.id}-${optIndex}">
                    <input 
                        type="radio" 
                        name="${q.id}" 
                        value="${optIndex}" 
                        onchange="selectQuizOption('${q.id}', ${optIndex})"
                    >
                    <span>${String.fromCharCode(65 + optIndex)}. ${opt}</span>
                </label>
            `;
        });

        card.innerHTML = `
            <div class="quiz-card-header">
                <span class="q-badge">${qIndex + 1}</span>
                <div class="q-title">
                    <strong>${q.title}</strong>
                    <p style="margin-top: 6px; font-weight: normal; color: #444;">${q.prompt}</p>
                </div>
            </div>
            <div class="quiz-options">
                ${optionsHtml}
            </div>
            <div class="quiz-feedback" id="feedback-${q.id}">
                <div class="feedback-status" id="feedback-status-${q.id}"></div>
                <div class="feedback-explanation" id="feedback-exp-${q.id}"></div>
            </div>
        `;

        container.appendChild(card);
    });
}

function selectQuizOption(qId, selectedIndex) {
    userAnswers[qId] = selectedIndex;

    const question = QUIZ_QUESTIONS.find(q => q.id === qId);
    if (!question) return;

    const feedbackBox = document.getElementById(`feedback-${qId}`);
    const statusBox = document.getElementById(`feedback-status-${qId}`);
    const expBox = document.getElementById(`feedback-exp-${qId}`);

    // Update selected styles on options
    question.options.forEach((_, idx) => {
        const optLabel = document.getElementById(`label-${qId}-${idx}`);
        if (optLabel) {
            optLabel.classList.remove("selected", "correct-option", "incorrect-option");
            if (idx === selectedIndex) {
                optLabel.classList.add("selected");
            }
        }
    });

    const isCorrect = (selectedIndex === question.correct);

    // Apply immediate visual feedback
    const chosenLabel = document.getElementById(`label-${qId}-${selectedIndex}`);
    const correctLabel = document.getElementById(`label-${qId}-${question.correct}`);

    if (isCorrect) {
        if (chosenLabel) chosenLabel.classList.add("correct-option");
        feedbackBox.className = "quiz-feedback show correct";
        statusBox.textContent = "✓ Correct Answer!";
    } else {
        if (chosenLabel) chosenLabel.classList.add("incorrect-option");
        if (correctLabel) correctLabel.classList.add("correct-option");
        feedbackBox.className = "quiz-feedback show incorrect";
        statusBox.textContent = `✗ Incorrect. The correct answer is Option ${String.fromCharCode(65 + question.correct)}.`;
    }

    expBox.innerHTML = `<strong>Technical Explanation:</strong> ${question.explanation}`;

    updateLiveScore();
}

function updateLiveScore() {
    let currentScore = 0;
    QUIZ_QUESTIONS.forEach(q => {
        if (userAnswers[q.id] !== undefined && userAnswers[q.id] === q.correct) {
            currentScore++;
        }
    });

    const scoreHeader = document.getElementById("quizScoreHeader");
    if (scoreHeader) {
        scoreHeader.textContent = `Score: ${currentScore} / ${QUIZ_QUESTIONS.length}`;
    }
}

function submitQuiz() {
    let score = 0;
    let answeredCount = 0;

    QUIZ_QUESTIONS.forEach(q => {
        const selected = userAnswers[q.id];
        if (selected !== undefined) {
            answeredCount++;
            if (selected === q.correct) {
                score++;
            }
        } else {
            // Trigger display of correct answer for unanswered questions
            const feedbackBox = document.getElementById(`feedback-${q.id}`);
            const statusBox = document.getElementById(`feedback-status-${q.id}`);
            const expBox = document.getElementById(`feedback-exp-${q.id}`);
            const correctLabel = document.getElementById(`label-${q.id}-${q.correct}`);

            if (correctLabel) correctLabel.classList.add("correct-option");
            if (feedbackBox) {
                feedbackBox.className = "quiz-feedback show incorrect";
                statusBox.textContent = `⚠ Not Answered. Correct answer is Option ${String.fromCharCode(65 + q.correct)}.`;
                expBox.innerHTML = `<strong>Technical Explanation:</strong> ${q.explanation}`;
            }
        }
    });

    const resultBox = document.getElementById("quizResult");
    resultBox.classList.remove("hidden");

    let evaluation = "";
    let badgeColor = "#8d6351";

    if (score === 10) {
        evaluation = "🌟 Perfect Score! Exceptional mastery of Triple DES architecture, Feistel operations, and S-box cryptanalysis.";
        badgeColor = "#2e6930";
    } else if (score >= 8) {
        evaluation = "👍 Great Job! Strong grasp of cryptography concepts and formula inversions. Review minor discrepancies above.";
        badgeColor = "#3b6d8c";
    } else if (score >= 5) {
        evaluation = "📖 Good Attempt. Review the Triple DES flowcharts and S-box lookup mechanisms to solidify understanding.";
        badgeColor = "#8d6351";
    } else {
        evaluation = "💡 Needs Revision. Revisit the Objectives, Theory, and S-Box sections, then re-attempt the quiz.";
        badgeColor = "#a33a32";
    }

    resultBox.innerHTML = `
        <h4 style="color: ${badgeColor};">Evaluation Results</h4>
        <div class="quiz-result-score" style="color: ${badgeColor};">${score} / ${QUIZ_QUESTIONS.length} (${(score / QUIZ_QUESTIONS.length) * 100}%)</div>
        <p style="font-size: 15px; max-width: 650px; margin: 12px auto; color: #444;">${evaluation}</p>
        <p style="font-size: 13px; color: #777;">Questions Answered: ${answeredCount} of ${QUIZ_QUESTIONS.length}</p>
    `;

    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function resetQuiz() {
    userAnswers = {};
    renderQuiz();
    const resultBox = document.getElementById("quizResult");
    if (resultBox) resultBox.classList.add("hidden");
    const scoreHeader = document.getElementById("quizScoreHeader");
    if (scoreHeader) scoreHeader.textContent = `Score: 0 / ${QUIZ_QUESTIONS.length}`;
}


/* =========================================================
   7. COLLAPSIBLE SIDEBAR & RESPONSIVE SCROLLSPY (Requirement 1)
   ========================================================= */

function toggleSidebar() {
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebarOverlay");
    const collapseIcon = document.getElementById("collapseIcon");

    if (window.innerWidth < 768) {
        // Mobile behavior: Drawer toggle with backdrop overlay
        const isOpen = sidebar.classList.contains("open");
        if (isOpen) {
            sidebar.classList.remove("open");
            if (overlay) overlay.classList.remove("active");
        } else {
            sidebar.classList.add("open");
            if (overlay) overlay.classList.add("active");
        }
    } else {
        // Desktop & Tablet behavior: Toggle between expanded (250px) & collapsed (68px)
        const isCollapsed = sidebar.classList.contains("collapsed");
        if (isCollapsed) {
            sidebar.classList.remove("collapsed");
            if (collapseIcon) collapseIcon.textContent = "◀";
        } else {
            sidebar.classList.add("collapsed");
            if (collapseIcon) collapseIcon.textContent = "▶";
        }
    }
}

function closeSidebar() {
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebarOverlay");
    if (sidebar) sidebar.classList.remove("open");
    if (overlay) overlay.classList.remove("active");
}


function setupScrollSpy() {
    const navLinks = document.querySelectorAll(".sidebar-menu .nav-link");
    const sectionIds = Array.from(navLinks).map(link => link.getAttribute("href").substring(1));
    const sections = sectionIds.map(id => document.getElementById(id)).filter(el => el !== null);

    const updateActiveNav = () => {
        let currentSectionId = "";
        const scrollPosition = window.scrollY + 140;
        const isNearBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 60;

        if (isNearBottom && sections.length > 0) {
            currentSectionId = sections[sections.length - 1].getAttribute("id");
        } else {
            // Find the deepest section in document order whose top has been scrolled past
            for (let i = sections.length - 1; i >= 0; i--) {
                const sectionTop = sections[i].getBoundingClientRect().top + window.scrollY;
                if (scrollPosition >= sectionTop) {
                    currentSectionId = sections[i].getAttribute("id");
                    break;
                }
            }
            if (!currentSectionId && sections.length > 0) {
                currentSectionId = sections[0].getAttribute("id");
            }
        }

        if (currentSectionId) {
            navLinks.forEach(link => {
                link.classList.remove("active");
                if (link.getAttribute("href") === `#${currentSectionId}`) {
                    link.classList.add("active");
                }
            });
        }
    };

    window.addEventListener("scroll", updateActiveNav, { passive: true });
    updateActiveNav();

    // Close mobile drawer when clicking a navigation link
    navLinks.forEach(link => {
        link.addEventListener("click", () => {
            if (window.innerWidth < 768) {
                closeSidebar();
            }
        });
    });

    // Window resize handler for responsive sidebar state consistency
    window.addEventListener("resize", () => {
        const sidebar = document.getElementById("sidebar");
        const collapseIcon = document.getElementById("collapseIcon");
        const overlay = document.getElementById("sidebarOverlay");

        if (window.innerWidth >= 768) {
            // Close mobile overlay if resizing up to tablet/desktop
            if (sidebar) sidebar.classList.remove("open");
            if (overlay) overlay.classList.remove("active");
            if (collapseIcon) {
                collapseIcon.textContent = sidebar.classList.contains("collapsed") ? "▶" : "◀";
            }
        }
    });
}


/* =========================================================
   8. LAB SHARE & INITIALIZATION
   ========================================================= */

function shareExperiment() {
    if (navigator.share) {
        navigator.share({
            title: "Double DES & Triple DES Virtual Lab",
            text: "Explore interactive Double DES, Triple DES (EDE), S-Boxes, and flowcharts.",
            url: window.location.href
        }).catch(() => {});
    } else {
        navigator.clipboard.writeText(window.location.href).then(() => {
            alert("Lab link successfully copied to clipboard!");
        });
    }
}

document.addEventListener("DOMContentLoaded", function() {

    // Initialize Triple DES mode selector
    changeTripleMode();

    // Initialize authentic S-Box calculation with default input
    calculateSBox();

    // Render 10 interactive quiz questions
    renderQuiz();

    // Setup collapsible sidebar and scrollspy
    setupScrollSpy();
});