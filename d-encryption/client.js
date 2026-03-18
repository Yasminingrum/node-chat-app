const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
const users = new Map();

// ── Generate RSA Key Pair ─────────────────────────────────────────────────────
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// ── Crypto Helpers ────────────────────────────────────────────────────────────

function hashMessage(message) {
  return crypto.createHash("sha256").update(message).digest("hex");
}

function signMessage(message) {
  const sign = crypto.createSign("SHA256");
  sign.update(message);
  sign.end();
  return sign.sign(privateKey, "base64");
}

function verifySignature(message, signature, senderPublicKey) {
  try {
    const verify = crypto.createVerify("SHA256");
    verify.update(message);
    verify.end();
    return verify.verify(senderPublicKey, signature, "base64");
  } catch {
    return false;
  }
}

function encryptMessage(message, recipientPublicKey) {
  return crypto.publicEncrypt(
    { key: recipientPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(message)
  ).toString("base64");
}

function decryptMessage(encryptedMessage) {
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(encryptedMessage, "base64")
  ).toString();
}

// ── Connect ───────────────────────────────────────────────────────────────────
socket.on("connect", () => {
  console.log("Connected to the server");
  console.log("[ Versi: D - Encryption ]");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);
    console.log(`Commands: !secret <username>  →  start secret chat`);
    console.log(`          !exit               →  stop secret chat\n`);

    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;

        if ((match = message.match(/^!secret (\w+)$/))) {
          targetUsername = match[1];
          if (!users.has(targetUsername)) {
            console.log(`User "${targetUsername}" tidak ditemukan di chat.`);
            targetUsername = "";
          } else {
            console.log(`Now secretly chatting with ${targetUsername}`);
            console.log(`(Pesan akan dienkripsi, hanya ${targetUsername} yang bisa membaca)`);
          }

        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";

        } else if (targetUsername) {
          // Mode secret: enkripsi pesan dengan public key target
          const recipientPublicKey = users.get(targetUsername);
          if (!recipientPublicKey) {
            console.log(`Tidak bisa menemukan public key milik ${targetUsername}.`);
          } else {
            const encryptedMessage = encryptMessage(message, recipientPublicKey);
            const hash = hashMessage(encryptedMessage);
            const signature = signMessage(encryptedMessage);
            socket.emit("message", {
              username,
              message: encryptedMessage,
              hash,
              signature,
              isEncrypted: true,
              target: targetUsername,
            });
            console.log(`[Secret → ${targetUsername}] Pesan terenkripsi dikirim.`);
          }

        } else {
          // Mode chat biasa
          const hash = hashMessage(message);
          const signature = signMessage(message);
          socket.emit("message", { username, message, hash, signature, isEncrypted: false });
        }
      }
      rl.prompt();
    });
  });
});

// ── Init ──────────────────────────────────────────────────────────────────────
socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

// ── New User ──────────────────────────────────────────────────────────────────
socket.on("newUser", (data) => {
  const { username: newUser, publicKey: newPublicKey } = data;
  users.set(newUser, newPublicKey);
  console.log(`${newUser} joined the chat`);
  rl.prompt();
});

// ── Terima & Verifikasi & Dekripsi Pesan ─────────────────────────────────────
socket.on("message", (data) => {
  const { username: senderUsername, message: receivedMessage, hash, signature, isEncrypted, target } = data;

  if (senderUsername === username) return;

  let warnings = [];

  // Cek #1: Hash
  const computedHash = hashMessage(receivedMessage);
  const hashValid = computedHash === hash;
  if (!hashValid) warnings.push("HASH MISMATCH: pesan mungkin dimodifikasi server");

  // Cek #2: Signature
  const senderPublicKey = users.get(senderUsername);
  if (!senderPublicKey) {
    warnings.push(`IMPERSONATION: ${senderUsername} tidak terdaftar`);
  } else {
    const sigValid = verifySignature(receivedMessage, signature, senderPublicKey);
    if (!sigValid) {
      warnings.push(!hashValid
        ? "SIGNATURE INVALID: server telah mengubah pesan"
        : `IMPERSONATION: ${senderUsername} this user is fake`
      );
    }
  }

  // Cek #3: Enkripsi
  if (isEncrypted) {
    if (target === username) {
      if (warnings.length > 0) {
        console.log(`\n[PESAN MENCURIGAKAN dari ${senderUsername}]`);
        warnings.forEach((w) => console.log(`   ⚠️  ${w}`));
      } else {
        try {
          const plaintext = decryptMessage(receivedMessage);
          console.log(`🔒 [Secret dari ${senderUsername}]: ${plaintext}`);
        } catch {
          console.log(`❌ Gagal mendekripsi pesan dari ${senderUsername}.`);
        }
      }
    } else {
      console.log(`🔒 [Secret ${senderUsername} → ${target}]: ${receivedMessage.slice(0, 40)}... (ciphertext)`);
    }
    rl.prompt();
    return;
  }

  if (warnings.length === 0) {
    console.log(`${senderUsername}: ${receivedMessage}`);
  } else {
    console.log(`\n[PESAN MENCURIGAKAN dari ${senderUsername}]`);
    console.log(`   Isi: "${receivedMessage}"`);
    warnings.forEach((w) => console.log(`   ⚠️  ${w}`));
  }
  rl.prompt();
});

// ── Disconnect ────────────────────────────────────────────────────────────────
socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});