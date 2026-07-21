import ExpoModulesCore
import CryptoKit

public class ExpoCryptoExtendedModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoCryptoExtended")

    AsyncFunction("deriveKey") { (ikmHex: String, saltHex: String, infoHex: String) -> String in
      guard let ikmData = Data(hex: ikmHex),
            let saltData = Data(hex: saltHex),
            let infoData = Data(hex: infoHex) else {
        throw Exception(name: "INVALID_HEX", description: "Invalid hex string provided")
      }

      let inputKey = SymmetricKey(data: ikmData)
      let derivedKey = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: inputKey,
        salt: saltData,
        info: infoData,
        outputByteCount: 32
      )

      return derivedKey.withUnsafeBytes { Data($0).hexString }
    }
  }
}

// Helper Extension for Hex Conversions
extension Data {
  init?(hex: String) {
    let len = hex.count / 2
    var data = Data(capacity: len)
    var ptr = hex.startIndex
    for _ in 0..<len {
      let nextPtr = hex.index(ptr, offsetBy: 2)
      guard let b = UInt8(hex[ptr..<nextPtr], radix: 16) else { return nil }
      data.append(b)
      ptr = nextPtr
    }
    self = data
  }

  var hexString: String {
    return map { String(format: "%02hhx", $0) }.joined()
  }
}