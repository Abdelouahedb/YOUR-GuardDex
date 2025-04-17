# GuardDex - AES Encryption/Decryption

![GuardDex Logo](https://github.com/Abdelouahedb/YOUR-GuardDex/blob/main/logo.png)

**GuardDex** is a tool designed for those who want to securely send or store private messages that only trusted individuals can read. Sometimes, we want to send or tweet something important, but we don’t want just anyone to be able to see it — only ourselves and a few others who have the key to decrypt the message. GuardDex provides an easy-to-use, secure solution for that.

It is an **AES encryption and decryption tool** with a simple graphical interface (GUI) that allows anyone to encrypt and decrypt text using AES encryption. Whether you're sending sensitive messages or protecting confidential data, **GuardDex** makes encryption easy and secure.

---

## Why GuardDex?

In today’s world, privacy matters. With so much information being exchanged over the internet, there’s always the risk of someone gaining unauthorized access to our data. Whether it’s a tweet, a private message, or an important note, sometimes we just want to make sure only a few trusted people can read it.

That's where encryption comes in. GuardDex provides a **simple and secure way to encrypt and decrypt messages** that are shared between you and those who have the key to unlock it.

---

## Features

- **AES Encryption & Decryption**: AES (Advanced Encryption Standard) is one of the most secure encryption algorithms available. GuardDex uses it to secure your messages, making them unreadable to anyone without the decryption key.
- **Simple & Intuitive Interface**: The application features a user-friendly GUI, so you don’t need to be a tech expert to encrypt and decrypt messages.
- **Secure Key Management**: You can safely enter your key to encrypt and decrypt data, ensuring that only those with the correct key can unlock your messages.
- **Base64 Encoding**: GuardDex encodes the encrypted data in Base64 format, making it easy to copy, paste, and share encrypted messages.

---

## Requirements

To use **GuardDex**, you need:

- Python 3.x
- PyQt5 (for GUI)
- cryptography (for encryption/decryption)

### Install Dependencies:

Install the required libraries by running:

```bash
pip install pyqt5 cryptography
  
## How to Use GuardDex

### Run the Application:
1. Install the required dependencies
2. Open the project folder and run `main.py` to launch the GUI

### Encrypt a Message:
1. Enter your plain text
2. Enter your encryption key (keep this secret!)
3. Click "Encrypt" to get the Base64-encoded message

### Decrypt a Message:
1. Paste the Base64-encoded message
2. Enter the decryption key (same as encryption key)
3. Click "Decrypt" to reveal the original message

### Copy & Share:
- Copy the encrypted message and share it via any medium
- Only recipients with the key can decrypt it

## Example Use Case
Protect sensitive documents or private conversations by encrypting messages. Only trusted recipients with the key can decrypt them, ensuring secure communication.

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/GuardDex.git
cd GuardDex
