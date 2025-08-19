const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

// Import your routes and configuration
const { initRoutes } = require("./routes"); // similar to init_routes in Python
const { Config } = require("./configuration"); // your Config object

// ── Express setup ─────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Serve static files from frontend folder
app.use(express.static(path.join(__dirname, "../frontend")));

// If you have HTML templates, you can set a view engine
// app.set("views", path.join(__dirname, "../frontend"));
// app.set("view engine", "ejs"); // optional if using EJS templates

// Use JSON parsing middleware
app.use(express.json());

// Apply configuration settings
app.set("config", Config);

// ── Initialize routes ─────────────────────────────────
initRoutes(app);

// ── Socket.IO events ────────────────────────────────
io.on("connection", (socket) => {
    socket.emit("alert", {
        message: "Connected to scam detection service",
        type: "success"
    });

    console.log("A client connected");
});

// ── Start server ────────────────────────────────────
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`Scam Detection backend starting on port ${PORT}…`);
});

