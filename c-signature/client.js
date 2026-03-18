const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";
const users = new Map();

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

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
  } catch { return false; }
}

socket.on("connect", () => {
  console.log("Connected to the server");
  console.log("[ Versi: C - Digital Signature ]");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);
    console.log(`Commands: !impersonate <username>  |  !exit\n`);

    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;
        if ((match = message.match(/^!impersonate (\w+)$/))) {
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          username = registeredUsername;
          console.log(`Now you are ${username}`);
        } else {
          const hash = hashMessage(message);
          const signature = signMessage(message);
          socket.emit("message", { username, message, hash, signature });
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUser, publicKey: newPublicKey } = data;
  users.set(newUser, newPublicKey);
  console.log(`${newUser} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: receivedMessage, hash, signature } = data;
  if (senderUsername === registeredUsername) return;

  let warnings = [];

  const computedHash = hashMessage(receivedMessage);
  if (computedHash !== hash) warnings.push("HASH MISMATCH: pesan mungkin dimodifikasi server");

  const senderPublicKey = users.get(senderUsername);
  if (!senderPublicKey) {
    warnings.push(`IMPERSONATION: ${senderUsername} tidak terdaftar`);
  } else {
    const sigValid = verifySignature(receivedMessage, signature, senderPublicKey);
    if (!sigValid) {
      warnings.push(computedHash !== hash
        ? "SIGNATURE INVALID: server telah mengubah pesan"
        : `IMPERSONATION: ${senderUsername}: this user is fake`
      );
    }
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