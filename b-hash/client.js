const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let username = "";

function hashMessage(message) {
  return crypto.createHash("sha256").update(message).digest("hex");
}

socket.on("connect", () => {
  console.log("Connected to the server");
  console.log("[ Versi: B - Hash Detection ]");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);
    console.log(`(Tidak ada command khusus — ketik pesan langsung)\n`);
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        const hash = hashMessage(message);
        socket.emit("message", { username, message, hash });
      }
      rl.prompt();
    });
  });
});

socket.on("message", (data) => {
  const { username: senderUsername, message: receivedMessage, hash } = data;
  if (senderUsername === username) return;

  const computedHash = hashMessage(receivedMessage);
  if (computedHash === hash) {
    console.log(`${senderUsername}: ${receivedMessage}`);
  } else {
    console.log(`\n⚠️  WARNING: Message from ${senderUsername} may have been changed during transmission!`);
    console.log(`   Received      : "${receivedMessage}"`);
    console.log(`   Expected hash : ${hash ? hash.slice(0, 20) + "..." : "tidak ada"}`);
    console.log(`   Computed hash : ${computedHash.slice(0, 20)}...`);
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