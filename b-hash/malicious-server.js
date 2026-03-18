const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer();
const io = socketIo(server);

const users = new Map();

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);

  socket.emit("init", Array.from(users.entries()));

  socket.on("registerPublicKey", (data) => {
    const { username, publicKey } = data;
    users.set(username, publicKey);
    console.log(`${username} registered with public key.`);
    io.emit("newUser", { username, publicKey });
  });

  // ⚠️ Server jahat: modifikasi isi pesan tapi teruskan hash & signature asli
  // → hash tidak akan cocok (ketahuan Assignment #1)
  // → signature tidak akan cocok karena pesan berubah (ketahuan Assignment #2)
  socket.on("message", (data) => {
    let { username, message, hash, signature } = data;
    message = message + " (sus?)"; // modifikasi pesan
    io.emit("message", { username, message, hash, signature });
  });

  socket.on("disconnect", () => {
    console.log(`Client ${socket.id} disconnected`);
  });
});

const port = 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});