import { ConfigPlugin } from "expo/config-plugins";
import type { ExpoCryptoExtendedConfigProps } from "./types";
/**
 * Expo Config Plugin to inject HKDF configuration properties into the app bundle context
 */
declare const withExpoCryptoExtended: ConfigPlugin<ExpoCryptoExtendedConfigProps>;
export default withExpoCryptoExtended;
