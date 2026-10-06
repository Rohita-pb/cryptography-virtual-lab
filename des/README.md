# Double DES & Triple DES Virtual Lab

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

Interactive demonstration of Double DES and Triple DES encryption
and decryption using one, two and three keys.

---

## Algorithms Covered

### 1. Double DES

Double DES applies DES encryption twice using two keys:

C = E(K2, E(K1, M))

Decryption:

M = D(K1, D(K2, C))

### 2. Triple DES

Triple DES uses the Encrypt-Decrypt-Encrypt (EDE) structure.

#### 1-Key Triple DES

K1 → K1 → K1

#### 2-Key Triple DES

K1 → K2 → K1

#### 3-Key Triple DES

K1 → K2 → K3

---

## Input

### Double DES

- Message
- Key 1
- Key 2

### Triple DES

- Message
- Number of keys
- Key 1
- Key 2, when applicable
- Key 3, when applicable

---

## Output

- Intermediate DES results
- Final ciphertext
- Decrypted plaintext
- Quiz score

---

## Required Libraries

CryptoJS 4.2.0

CDN:

https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js

---

## Technologies

- HTML5
- CSS3
- JavaScript
- CryptoJS

---

## Features

- Interactive Double DES encryption
- Interactive Double DES decryption
- 1-key Triple DES
- 2-key Triple DES
- 3-key Triple DES
- Step-by-step encryption visualization
- Step-by-step decryption visualization
- Input validation
- Clear/reset functionality
- Test cases
- Interactive quiz
- Responsive design
- Common brown/cream virtual-lab theme

---

## Key Format

The experiment accepts DES keys as:

16 hexadecimal characters

Example:

0123456789ABCDEF

This represents an 8-byte DES key.

---

## Test Cases

### Double DES

1. Message: Hello World
2. Message: Cryptography
3. Message: Test Message

Expected result:

The decrypted message should match the original message.

### Triple DES

1. 1-Key Triple DES
2. 2-Key Triple DES
3. 3-Key Triple DES

Expected result:

The decrypted message should match the original message.

---

## Validation Tests

The following invalid inputs should be tested:

- Empty message
- Missing Key 1
- Missing Key 2
- Missing Key 3
- Key containing non-hexadecimal characters
- Key containing fewer than 16 hexadecimal characters
- Key containing more than 16 hexadecimal characters

---

## Browser Requirements

The experiment can be run using a modern web browser such as:

- Google Chrome
- Microsoft Edge
- Mozilla Firefox

An internet connection is required when using the CryptoJS CDN.

---

## Integration

This module is designed to be integrated into the main
Cryptography Virtual Laboratory application.

The integration team should link:

`/experiments/des/`

to the experiment's navigation card.

---

## Files

```text
des/
├── index.html
├── style.css
├── script.js
└── README.md