import {
  withInfoPlist,
  withAndroidManifest,
  AndroidConfig,
  ConfigPlugin,
} from "expo/config-plugins";

import type { ExpoCryptoExtendedConfigProps } from "./types";

const DEFAULT_SALT = "karr-e2e-v1-salt";
const DEFAULT_INFO = "karr-e2e-v1-aes-gcm-key";

/**
 * Expo Config Plugin to inject HKDF configuration properties into the app bundle context
 */
const withExpoCryptoExtended: ConfigPlugin<ExpoCryptoExtendedConfigProps> = (
  config,
  { salt, info } = {
    salt: DEFAULT_SALT,
    info: DEFAULT_INFO,
  },
) => {
  const mSalt = salt || DEFAULT_SALT;
  const mInfo = info || DEFAULT_INFO;

  config = withInfoPlist(config, (config) => {
    config.modResults["EXPO_CRYPTO_EXTENDED_SALT"] = mSalt;
    config.modResults["EXPO_CRYPTO_EXTENDED_INFO"] = mInfo;
    return config;
  });

  config = withAndroidManifest(config, (config) => {
    const mainApplication = AndroidConfig.Manifest.getMainApplicationOrThrow(
      config.modResults,
    );

    AndroidConfig.Manifest.addMetaDataItemToMainApplication(
      mainApplication,
      "EXPO_CRYPTO_EXTENDED_SALT",
      mSalt,
    );

    AndroidConfig.Manifest.addMetaDataItemToMainApplication(
      mainApplication,
      "EXPO_CRYPTO_EXTENDED_INFO",
      mInfo,
    );
    return config;
  });

  // Inject these properties directly into the expo runtime constants block
  if (!config.extra) config.extra = {};

  config.extra.ExpoCryptoExtended = {
    salt: mSalt,
    info: mInfo,
  };

  return config;
};

export default withExpoCryptoExtended;
