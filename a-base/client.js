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

// Menyimpan username → publicKey semua user
const users = new Map();

// ── Generate RSA Key Pair saat client start ───────────────────────────────────
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// ── Crypto Helpers ────────────────────────────────────────────────────────────

// Assignment #1: SHA-256 hash untuk deteksi modifikasi server
function hashMessage(message) {
  return crypto.createHash("sha256").update(message).digest("hex");
}

// Assignment #2: Tanda tangani pesan dengan private key kita
function signMessage(message) {
  const sign = crypto.createSign("SHA256");
  sign.update(message);
  sign.end();
  return sign.sign(privateKey, "base64");
}

// Assignment #2: Verifikasi signature dengan public key pengirim
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

// Assignment #3: Enkripsi pesan dengan public key target (RSA-OAEP)
// Hanya pemilik private key target yang bisa mendekripsi
function encryptMessage(message, recipientPublicKey) {
  return crypto.publicEncrypt(
    { key: recipientPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(message)
  ).toString("base64");
}

// Assignment #3: Dekripsi pesan dengan private key kita sendiri
function decryptMessage(encryptedMessage) {
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(encryptedMessage, "base64")
  ).toString();
}

// ── Connect ───────────────────────────────────────────────────────────────────
socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);
    console.log(`Commands: !secret <username>  →  start secret chat`);
    console.log(`          !exit               →  stop secret chat\n`);

    // Daftarkan public key kita ke server
    socket.emit("registerPublicKey", { username, publicKey });

    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;

        if ((match = message.match(/^!secret (\w+)$/))) {
          // Mulai secret chat ke target
          targetUsername = match[1];
          if (!users.has(targetUsername)) {
            console.log(`User "${targetUsername}" tidak ditemukan di chat.`);
            targetUsername = "";
          } else {
            console.log(`Now secretly chatting with ${targetUsername}`);
            console.log(`(Pesan akan dienkripsi, hanya ${targetUsername} yang bisa membaca)`);
          }

        } else if (message.match(/^!exit$/)) {
          // Keluar dari mode secret chat
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";

        } else if (targetUsername) {
          // ── MODE SECRET CHAT ──────────────────────────────────────────────
          const recipientPublicKey = users.get(targetUsername);
          if (!recipientPublicKey) {
            console.log(`Tidak bisa menemukan public key milik ${targetUsername}.`);
          } else {
            // Enkripsi pesan dengan public key target
            const encryptedMessage = encryptMessage(message, recipientPublicKey);

            // Hash & sign dari CIPHERTEXT (bukan plaintext)
            // → membuktikan kita yang mengirim ciphertext ini, dan ciphertext tidak diubah
            const hash = hashMessage(encryptedMessage);
            const signature = signMessage(encryptedMessage);

            socket.emit("message", {
              username,
              message: encryptedMessage,   // yang dikirim ke server adalah ciphertext
              hash,
              signature,
              isEncrypted: true,           // flag agar penerima tahu ini perlu didekripsi
              target: targetUsername,      // info siapa target penerima
            });

            console.log(`[Secret → ${targetUsername}] Pesan terenkripsi dikirim.`);
          }

        } else {
          // ── MODE CHAT BIASA ───────────────────────────────────────────────
          const hash = hashMessage(message);
          const signature = signMessage(message);
          socket.emit("message", { username, message, hash, signature, isEncrypted: false });
        }
      }
      rl.prompt();
    });
  });
});

// ── Init: terima daftar user yang sudah ada ───────────────────────────────────
socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

// ── User baru bergabung ───────────────────────────────────────────────────────
socket.on("newUser", (data) => {
  const { username: newUser, publicKey: newPublicKey } = data;
  users.set(newUser, newPublicKey);
  console.log(`${newUser} joined the chat`);
  rl.prompt();
});

// ── Terima & Verifikasi & (jika perlu) Dekripsi Pesan ────────────────────────
socket.on("message", (data) => {
  const {
    username: senderUsername,
    message: receivedMessage,
    hash,
    signature,
    isEncrypted,
    target,
  } = data;

  // Abaikan pesan dari diri sendiri
  if (senderUsername === username) return;

  let warnings = [];

  // ── Cek #1 (Assignment #1): Verifikasi Hash ──────────────────────────────
  // Hash selalu dibuat dari apa yang dikirim (plaintext atau ciphertext)
  const computedHash = hashMessage(receivedMessage);
  const hashValid = computedHash === hash;
  if (!hashValid) {
    warnings.push("HASH MISMATCH: pesan mungkin dimodifikasi server");
  }

  // ── Cek #2 (Assignment #2): Verifikasi Signature ─────────────────────────
  const senderPublicKey = users.get(senderUsername);
  let sigValid = false;
  if (!senderPublicKey) {
    warnings.push(`IMPERSONATION: ${senderUsername} tidak terdaftar`);
  } else {
    sigValid = verifySignature(receivedMessage, signature, senderPublicKey);
    if (!sigValid) {
      if (!hashValid) {
        warnings.push("SIGNATURE INVALID: server telah mengubah pesan");
      } else {
        warnings.push(`IMPERSONATION: ${senderUsername} this user is fake`);
      }
    }
  }

  // ── Assignment #3: Dekripsi jika pesan terenkripsi ───────────────────────
  if (isEncrypted) {
    if (target === username) {
      // Pesan ini ditujukan untuk kita → coba dekripsi
      if (warnings.length > 0) {
        // Ada warning keamanan → tetap tampilkan tapi beri peringatan
        console.log(`\n[PESAN MENCURIGAKAN dari ${senderUsername}]`);
        warnings.forEach((w) => console.log(`   ⚠️  ${w}`));
        rl.prompt();
      } else {
        try {
          const plaintext = decryptMessage(receivedMessage);
          console.log(`🔒 [Secret dari ${senderUsername}]: ${plaintext}`);
        } catch {
          console.log(`\n❌ Gagal mendekripsi pesan dari ${senderUsername}.`);
          console.log(`   (Pesan mungkin tidak ditujukan untuk kita, atau rusak)`);
        }
        rl.prompt();
      }
    } else {
      // Pesan terenkripsi tapi bukan untuk kita → tampilkan ciphertext saja
      const preview = receivedMessage.slice(0, 40);
      console.log(`🔒 [Secret ${senderUsername} → ${target}]: ${preview}... (ciphertext)`);
      rl.prompt();
    }
    return;
  }

  // ── Pesan biasa (tidak terenkripsi) ──────────────────────────────────────
  if (warnings.length === 0) {
    console.log(`${senderUsername}: ${receivedMessage}`);
  } else {
    console.log(`\n[PESAN MENCURIGAKAN dari ${senderUsername}]`);
    console.log(`   Isi pesan: "${receivedMessage}"`);
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