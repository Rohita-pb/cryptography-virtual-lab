# Double DES & Triple DES Virtual Lab

🌐 **Live Demo:** [https://rohita-pb.github.io/cryptography-virtual-lab/des/](https://rohita-pb.github.io/cryptography-virtual-lab/des/)

## Group

Group DES

---

## Experiment ID

EXP-DES

---

## Experiment Name

Double DES & Triple DES

---

## Folder

`/experiments/des/`

---

## Entry File

`index.html`

---

## Navigation Title

Double DES & Triple DES

---

## Short Description

Interactive demonstration of Double DES and Triple DES encryption and decryption using one, two, and three keys, including standard 3-Key EDE flowcharts, authentic DES S-Box 1 lookup, and engineering self-assessment.

---

## Algorithms Covered

### 1. Data Encryption Standard (DES)
DES is a 16-round Feistel symmetric-key block cipher operating on 64-bit blocks with a 56-bit effective key. Non-linear S-boxes provide Confusion, while P-boxes provide Diffusion.

### 2. Double DES
Double DES applies DES encryption twice using two independent keys:

```text
C = E(K2, E(K1, P))
P = D(K1, D(K2, C))
```

*Vulnerability:* Susceptible to the Meet-in-the-Middle (MitM) attack, reducing effective security to $2^{57}$ operations rather than $2^{112}$.

### 3. Triple DES (3-Key EDE Architecture)
Triple DES applies the Encrypt–Decrypt–Encrypt (EDE) structure using three independent keys: K1, K2, and K3.

- **Encryption Formula:**
  $$C = E(K_3, D(K_2, E(K_1, P)))$$
- **Decryption Formula:**
  $$P = D(K_1, E(K_2, D(K_3, C)))$$

#### Mathematical Notation:
- **P** = Plaintext block (64 bits)
- **C** = Ciphertext block (64 bits)
- **E(K, X)** = DES encryption of X using key K
- **D(K, X)** = DES decryption of X using key K
- **K1, K2, K3** = The three independent DES keys (56 bits each)

#### Triple DES Key Configurations:
- **1-Key Triple DES:** $K1 \to K1 \to K1$ ($E(K1) \to D(K1) \to E(K1)$). Backward compatible with single DES.
- **2-Key Triple DES:** $K1 \to K2 \to K1$ ($E(K1) \to D(K2) \to E(K1)$). 112-bit effective security.
- **3-Key Triple DES:** $K1 \to K2 \to K3$ ($E(K1) \to D(K2) \to E(K3)$). Standard NIST SP 800-67 specification.

---

## Key Features

1. **Collapsible Responsive Sidebar Navigation & Layout:**
   - Smooth desktop collapsible rail (68px / 256px) with tooltips and mobile slide-out drawer with overlay.
   - Evenly spaced navigation items with prominent active section indicators.
   - Refined header alignment, balanced card proportions, and zero horizontal page overflow.
   - Dynamic scrollspy active section highlighting.

2. **Refined Objectives:**
   - Focused engineering learning objectives centered on multi-stage DES execution and recovery verification.

3. **Prominent 3-Key Triple DES Formula Card:**
   - Formal mathematical definitions for both encryption and decryption.
   - Step-by-step breakdown of intermediate outputs:
     - Encryption: $X_1 = E(K_1, P)$, $X_2 = D(K_2, X_1)$, $C = E(K_3, X_2)$.
     - Decryption: $Y_1 = D(K_3, C)$, $Y_2 = E(K_2, Y_1)$, $P = D(K_1, Y_2)$.
   - Clear rationale for the EDE construction over EEE.

4. **Interactive Three-Key DES Flowchart:**
   - Visual block diagram for the Encryption pipeline ($P \to X_1 \to X_2 \to C$).
   - Reverse Decryption pipeline ($C \to Y_1 \to Y_2 \to P$).
   - Color-coded operations and intermediate output tags.

5. **Authentic DES S-Box 1 (S1) Module:**
   - Complete 4×16 lookup matrix verified against NIST FIPS PUB 46-3.
   - Explanation of 6-bit to 4-bit non-linear substitution.
   - Addressing explanation: outer bits $(b_1 b_6)_2$ determine Row; middle bits $(b_2 b_3 b_4 b_5)_2$ determine Column.
   - Interactive calculator with 6-bit validation, bit pill diagrams, and dynamic table highlighting of Row, Column, and target cell.

6. **10-Question Cryptography Engineering Quiz:**
   - Covers Triple DES order of operations, formula inversion, key order non-commutativity, flowchart analysis, S-box calculations, binary-to-decimal conversion, and Shannon's confusion/diffusion principles.
   - Immediate feedback on each question with technical reasoning and explanations.
   - Real-time score tracker and comprehensive performance evaluation.

---

## Input Specifications

- **Plaintext:** Arbitrary string (automatically padded via PKCS#7 to 64-bit blocks).
- **DES Keys:** 16 hexadecimal characters (64 bits, representing 56 key bits + 8 parity bits).
  - Example: `0123456789ABCDEF`
- **S-Box Input:** Exactly 6 binary digits (`0` or `1`).
  - Example: `011011`

---

## Required Libraries

- **CryptoJS 4.2.0**
  CDN: `https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js`

---

## Technologies Used

- **HTML5:** Semantic layout and structured data elements.
- **CSS3:** Custom responsive layout, flexbox, grid, glassmorphic accents, and smooth animations.
- **JavaScript (ES6):** Cryptographic orchestration, S-Box matrix arithmetic, quiz engine, and DOM interaction.

---

## File Structure

```text
des/
├── Dockerfile        # Containerized Nginx deployment
├── index.html        # Main virtual lab entry point
├── style.css         # Styling and responsive design
├── script.js         # Cryptographic engine, S-box & quiz logic
└── README.md         # Experiment documentation & reference manual
```