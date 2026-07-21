/**
 * Expo Config Plugin to inject HKDF configuration properties into the app bundle context
 */
module.exports = function withExpoCryptoExtended(config, props = {}) {
  // Read constants from props, or use the static defaults from the task description
  const salt = props.salt || "karr-e2e-v1-salt";
  const info = props.info || "karr-e2e-v1-aes-gcm-key";

  // Inject these properties directly into the expo runtime constants block
  if (!config.extra) config.extra = {};
  
  config.extra.ExpoCryptoExtended = {
    salt: salt,
    info: info
  };

  return config;
};