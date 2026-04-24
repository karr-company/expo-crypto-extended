import {
  decrypt,
  encrypt,
  generateKeyPair,
  type EncryptedPayload,
  type EncryptedPayloadWithNonce,
} from "@karr-company/expo-crypto-extended";
import { useState } from "react";
import { Button, ScrollView, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

const SALT = "example-salt-v1";
const INFO = "example-info-v1";
const PLAINTEXT = "Hello world! 👋";

export default function App() {
  const [combinedPayload, setCombinedPayload] = useState<EncryptedPayload | null>(null);
  const [noncePayload, setNoncePayload] = useState<EncryptedPayloadWithNonce | null>(null);
  const [combinedPlaintext, setCombinedPlaintext] = useState<string>("");
  const [noncePlaintext, setNoncePlaintext] = useState<string>("");
  const [error, setError] = useState<string>("");

  const runDemo = async () => {
    try {
      setError("");
      setCombinedPlaintext("");
      setNoncePlaintext("");

      const receiver = await generateKeyPair();

      const payloadCombined = await encrypt(
        PLAINTEXT,
        receiver.publicKey,
        SALT,
        INFO,
      );
      setCombinedPayload(payloadCombined);

      const decryptedCombined = await decrypt(
        payloadCombined,
        receiver.privateKey,
        SALT,
        INFO,
      );
      setCombinedPlaintext(decryptedCombined);

      const payloadWithNonce = await encrypt(
        PLAINTEXT,
        receiver.publicKey,
        SALT,
        INFO,
        { withNonce: true },
      );
      setNoncePayload(payloadWithNonce);

      const decryptedWithNonce = await decrypt(
        payloadWithNonce,
        receiver.privateKey,
        SALT,
        INFO,
      );
      setNoncePlaintext(decryptedWithNonce);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.header}>expo-crypto-extended example</Text>
        <Text style={styles.subheader}>Demonstrates both payload formats for encrypt/decrypt.</Text>

        <Button title="Run Encrypt/Decrypt Demo" onPress={runDemo} />

        <Group title="Combined payload (nonce embedded)">
          <LabelValue label="ciphertext" value={combinedPayload?.ciphertext} />
          <LabelValue label="ephemeralPublicKey" value={combinedPayload?.ephemeralPublicKey} />
          <LabelValue label="decrypted" value={combinedPlaintext} />
        </Group>

        <Group title="Payload with explicit nonce">
          <LabelValue label="nonce" value={noncePayload?.nonce} />
          <LabelValue label="ciphertext" value={noncePayload?.ciphertext} />
          <LabelValue label="ephemeralPublicKey" value={noncePayload?.ephemeralPublicKey} />
          <LabelValue label="decrypted" value={noncePlaintext} />
        </Group>

        {error ? (
          <View style={styles.errorBox}>
            <Text style={styles.errorTitle}>Error</Text>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        ) : null}
      </ScrollView>
    </SafeAreaView>
  );
}

function Group(props: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.group}>
      <Text style={styles.groupTitle}>{props.title}</Text>
      {props.children}
    </View>
  );
}

function LabelValue(props: { label: string; value?: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.label}>{props.label}</Text>
      <Text style={styles.value} selectable>
        {props.value ?? "-"}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#f5f5f5",
  },
  content: {
    gap: 12,
    padding: 16,
    paddingBottom: 28,
  },
  header: {
    fontSize: 24,
    fontWeight: "700",
  },
  subheader: {
    color: "#555",
  },
  group: {
    gap: 8,
    borderRadius: 12,
    backgroundColor: "#fff",
    padding: 12,
  },
  groupTitle: {
    fontSize: 16,
    fontWeight: "600",
  },
  row: {
    gap: 4,
  },
  label: {
    color: "#666",
    fontSize: 12,
    fontWeight: "600",
  },
  value: {
    color: "#111",
    fontSize: 12,
  },
  errorBox: {
    borderRadius: 12,
    backgroundColor: "#fee2e2",
    padding: 12,
  },
  errorTitle: {
    color: "#991b1b",
    fontWeight: "700",
  },
  errorText: {
    color: "#991b1b",
  },
});
