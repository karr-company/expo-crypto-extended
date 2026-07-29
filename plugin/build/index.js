"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const config_plugins_1 = require("expo/config-plugins");
const DEFAULT_SALT = "karr-e2e-v1-salt";
const DEFAULT_INFO = "karr-e2e-v1-aes-gcm-key";
/**
 * Expo Config Plugin to inject HKDF configuration properties into the app bundle context
 */
const withExpoCryptoExtended = (config, { salt, info } = {
    salt: DEFAULT_SALT,
    info: DEFAULT_INFO,
}) => {
    const mSalt = salt || DEFAULT_SALT;
    const mInfo = info || DEFAULT_INFO;
    config = (0, config_plugins_1.withInfoPlist)(config, (config) => {
        config.modResults["EXPO_CRYPTO_EXTENDED_SALT"] = mSalt;
        config.modResults["EXPO_CRYPTO_EXTENDED_INFO"] = mInfo;
        return config;
    });
    config = (0, config_plugins_1.withAndroidManifest)(config, (config) => {
        const mainApplication = config_plugins_1.AndroidConfig.Manifest.getMainApplicationOrThrow(config.modResults);
        config_plugins_1.AndroidConfig.Manifest.addMetaDataItemToMainApplication(mainApplication, "EXPO_CRYPTO_EXTENDED_SALT", mSalt);
        config_plugins_1.AndroidConfig.Manifest.addMetaDataItemToMainApplication(mainApplication, "EXPO_CRYPTO_EXTENDED_INFO", mInfo);
        return config;
    });
    // Inject these properties directly into the expo runtime constants block
    if (!config.extra)
        config.extra = {};
    config.extra.ExpoCryptoExtended = {
        salt: mSalt,
        info: mInfo,
    };
    return config;
};
exports.default = withExpoCryptoExtended;
