// app.js
const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { initRoutes } = require("./routes");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET","POST"] } });

// Serve frontend folder (if needed)
app.use(express.static(path.join(__dirname, "../frontend")));

// JSON parser middleware
app.use(express.json());

// Initialize routes
initRoutes(app);

// Socket.IO connection
io.on("connection", (socket) => {
  console.log("Client connected");
  socket.emit("alert", { message: "Connected to scam detection service", type: "success" });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Backend running at http://localhost:${PORT}`));
