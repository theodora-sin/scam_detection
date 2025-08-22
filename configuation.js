// Simple configuration object
const Config = {
  PORT: process.env.PORT || 5000,
  FERNET_KEY_PATH: process.env.FERNET_KEY_PATH || "fernet.key",
};

module.exports = { Config };
