import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

/**
 * HsmDocumentSigner — HSM-Backed Digital Document Signing Service
 *
 * Demonstrates a real-world use case: generating an RSA-4096 key pair inside an
 * Entrust nShield HSM via the nCipherKM JCA/JCE provider, signing documents
 * with
 * SHA384withRSA, and verifying signatures — all while the private key NEVER
 * leaves
 * the HSM boundary.
 *
 * Industry applications of this pattern:
 * - Code signing (JAR, EXE, MSI)
 * - PDF digital signatures (PAdES)
 * - API request signing (financial, healthcare)
 * - Certificate Authority issuance
 * - Timestamping Authority (TSA) services
 *
 * Usage:
 * # Compile
 * javac --module-path "%NFAST_HOME%\java\classes" -d out
 * src\HsmDocumentSigner.java
 *
 * # Run (module-protected keys — no smartcard needed)
 * java --module-path "%NFAST_HOME%\java\classes" ^
 * -Dprotect=module -DignorePassphrase=true ^
 * -cp out HsmDocumentSigner
 *
 * # Run (OCS-protected keys — requires smartcard)
 * java --module-path "%NFAST_HOME%\java\classes" ^
 * -Dprotect=cardset ^
 * -cp out HsmDocumentSigner
 *
 * Prerequisites:
 * - nShield Security World created and HSM in 'Usable' state
 * - nCipherKM registered as provider #1 in java.security
 * - hardserver running on ports 9000/9001
 *
 * 
 */
public class HsmDocumentSigner {

    // ──────────────────────────────────────────────────────────────────────
    // Configuration
    // ──────────────────────────────────────────────────────────────────────

    /** JCA provider name — must match the registered nCipherKM provider. */
    private static final String PROVIDER = "nCipherKM";

    /** nShield KeyStore type — keys live in the Security World, not on disk. */
    private static final String KEYSTORE_TYPE = "nCipher.sworld";

    /** Signature algorithm: SHA-384 digest + RSA signing (FIPS 140-3 approved). */
    private static final String SIGNATURE_ALGORITHM = "SHA384withRSA";

    /** RSA key size — 4096-bit for long-lived signing keys. */
    private static final int RSA_KEY_SIZE = 4096;

    /** Alias under which the signing key is stored in the nShield KeyStore. */
    private static final String KEY_ALIAS = "document-signing-key";

    /**
     * Path to the nShield KeyStore file (namespace identifiers only — no key
     * material).
     */
    private static final String KEYSTORE_PATH = "document-signer.nck";

    // ──────────────────────────────────────────────────────────────────────
    // Main
    // ──────────────────────────────────────────────────────────────────────

    public static void main(String[] args) {
        try {
            System.out.println("╔══════════════════════════════════════════════════════════╗");
            System.out.println("║   HSM-Backed Document Signing Service                    ║");
            System.out.println("║   Provider: nCipherKM  │  HSM: nShield 5c                ║");
            System.out.println("╚══════════════════════════════════════════════════════════╝");
            System.out.println();

            // ── Step 0: Verify the nCipherKM provider is available ──────────
            verifyProvider();

            // ── Step 1: Load or create the nShield KeyStore ────────────────
            char[] passphrase = getPassphrase();
            KeyStore keyStore = loadOrCreateKeyStore(passphrase);

            // ── Step 2: Get or generate the signing key pair ───────────────
            KeyPair keyPair;
            if (keyStore.containsAlias(KEY_ALIAS)) {
                System.out.println("[*] Found existing signing key: " + KEY_ALIAS);
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, passphrase);
                Certificate cert = keyStore.getCertificate(KEY_ALIAS);
                PublicKey publicKey = cert.getPublicKey();
                keyPair = new KeyPair(publicKey, privateKey);
                printKeyInfo(keyPair);
            } else {
                System.out.println("[*] No existing key found. Generating RSA-" + RSA_KEY_SIZE
                        + " key pair on HSM...");
                keyPair = generateKeyPairOnHsm();
                storeKeyInKeyStore(keyStore, keyPair, passphrase);
                System.out.println("[+] Key generated and stored in nShield Security World.");
            }

            // ── Step 3: Sign a sample document ─────────────────────────────
            byte[] document = createSampleDocument();
            System.out.println("\n[*] Signing document (" + document.length + " bytes) with "
                    + SIGNATURE_ALGORITHM + "...");
            System.out.println("    (Signing operation executes INSIDE the nShield HSM)");

            long signStart = System.nanoTime();
            byte[] signature = signDocument(keyPair.getPrivate(), document);
            long signMs = (System.nanoTime() - signStart) / 1_000_000;

            System.out.println("[+] Signature produced: " + signature.length + " bytes ("
                    + signMs + " ms)");
            System.out.println("    Base64: " + Base64.getEncoder().encodeToString(signature)
                    .substring(0, 64) + "...");

            // ── Step 4: Verify the signature ───────────────────────────────
            System.out.println("\n[*] Verifying signature...");
            boolean valid = verifySignature(keyPair.getPublic(), document, signature);
            System.out.println(valid
                    ? "[+] PASS - Signature is VALID"
                    : "[-] FAIL - Signature is INVALID");

            // ── Step 5: Tamper detection demo ──────────────────────────────
            System.out.println("\n[*] Tamper detection test -- modifying one byte...");
            byte[] tampered = document.clone();
            tampered[0] ^= 0xFF; // Flip one byte
            boolean tamperedValid = verifySignature(keyPair.getPublic(), tampered, signature);
            System.out.println(tamperedValid
                    ? "[-] FAIL - Tampered document was accepted!"
                    : "[+] PASS - Tampered document correctly REJECTED");

            // ── Step 6: Batch signing benchmark ────────────────────────────
            System.out.println("\n[*] Batch signing benchmark (10 documents)...");
            benchmarkSigning(keyPair.getPrivate(), 10);

            // ── Step 7: Export public key for external verifiers ────────────
            exportPublicKey(keyPair.getPublic());

            // ── Summary ────────────────────────────────────────────────────
            System.out.println("\n╔══════════════════════════════════════════════════════════╗");
            System.out.println("║   All operations completed successfully.                 ║");
            System.out.println("║                                                          ║");
            System.out.println("║   - Private key NEVER left the HSM boundary              ║");
            System.out.println("║   - All signing operations executed on nShield hardware  ║");
            System.out.println("║   - Key persisted in nShield Security World (KeyStore)   ║");
            System.out.println("╚══════════════════════════════════════════════════════════╝");

        } catch (Exception e) {
            System.err.println("\n[!] ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Provider Verification
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Verifies that the nCipherKM provider is installed and lists all registered
     * security providers for diagnostic purposes.
     */
    private static void verifyProvider() throws Exception {
        System.out.println("[*] Checking security providers...");

        Provider nCipherProvider = Security.getProvider(PROVIDER);
        if (nCipherProvider == null) {
            throw new RuntimeException(
                    "nCipherKM provider not found! Ensure it is registered in java.security "
                            + "and the nShield Security World is operational.");
        }

        System.out.println("[+] nCipherKM provider found: " + nCipherProvider.getName()
                + " v" + nCipherProvider.getVersionStr());
        System.out.println("    " + nCipherProvider.getInfo());

        // List all providers for diagnostics
        System.out.println("\n    Registered providers:");
        for (Provider p : Security.getProviders()) {
            String marker = p.getName().equals(PROVIDER) ? " <-- (active)" : "";
            System.out.println("      " + p.getName() + " v" + p.getVersionStr() + marker);
        }
        System.out.println();
    }

    // ──────────────────────────────────────────────────────────────────────
    // KeyStore Operations
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Loads an existing nShield KeyStore or creates a new one.
     *
     * The nCipher.sworld KeyStore stores only namespace identifiers on disk —
     * all actual key material resides in the Security World (inside the HSM).
     */
    private static KeyStore loadOrCreateKeyStore(char[] passphrase) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        File ksFile = new File(KEYSTORE_PATH);

        if (ksFile.exists()) {
            System.out.println("[*] Loading existing KeyStore: " + ksFile.getAbsolutePath());
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                ks.load(fis, passphrase);
            }
            System.out.println("[+] KeyStore loaded. Entries: " + ks.size());
        } else {
            System.out.println("[*] Creating new nShield KeyStore: " + ksFile.getAbsolutePath());
            ks.load(null, passphrase); // null InputStream = create new KeyStore
            System.out.println("[+] New KeyStore created.");
        }
        return ks;
    }

    /**
     * Stores a key pair in the nShield KeyStore with a self-signed certificate.
     *
     * The JCE requires a certificate chain to store private keys. We generate a
     * self-signed X.509 certificate for this purpose. In production, this would
     * be replaced with a CA-issued certificate.
     */
    private static void storeKeyInKeyStore(KeyStore keyStore, KeyPair keyPair,
            char[] passphrase) throws Exception {
        // Generate a self-signed certificate (required by KeyStore API)
        Certificate selfSignedCert = generateSelfSignedCert(keyPair);
        Certificate[] certChain = new Certificate[] { selfSignedCert };

        // Store the private key + certificate chain under our alias
        keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), passphrase, certChain);

        // Persist the KeyStore to disk
        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            keyStore.store(fos, passphrase);
        }
        System.out.println("[+] Key stored as alias '" + KEY_ALIAS + "' in " + KEYSTORE_PATH);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Key Generation (on HSM)
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Generates an RSA key pair INSIDE the nShield HSM.
     *
     * The private key never leaves the HSM boundary. The returned PrivateKey
     * object is a handle/proxy — it references the key inside the Security World
     * but contains no actual key material on the host.
     *
     * @return KeyPair with HSM-resident private key and extractable public key
     */
    private static KeyPair generateKeyPairOnHsm() throws Exception {
        System.out.println("    Algorithm: RSA-" + RSA_KEY_SIZE);
        System.out.println("    Provider:  " + PROVIDER + " (nShield HSM)");
        System.out.println("    Protection: " + System.getProperty("protect", "module"));

        // Request the KeyPairGenerator from the nCipherKM provider specifically
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PROVIDER);
        kpg.initialize(RSA_KEY_SIZE);

        long start = System.nanoTime();
        KeyPair keyPair = kpg.generateKeyPair();
        long elapsed = (System.nanoTime() - start) / 1_000_000;

        System.out.println("[+] RSA-" + RSA_KEY_SIZE + " key pair generated on HSM (" + elapsed + " ms)");
        printKeyInfo(keyPair);
        return keyPair;
    }

    /**
     * Prints key metadata for verification. Note that the private key's toString()
     * will NOT reveal key material — the nCipherKM provider returns a proxy object.
     */
    private static void printKeyInfo(KeyPair kp) {
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();
        System.out.println("    Public key:  " + pub.getAlgorithm() + " / " + pub.getFormat());
        System.out.println("    Private key: " + priv.getAlgorithm() + " / " + priv.getFormat()
                + " (HSM-resident handle)");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Signing & Verification
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Signs document bytes using the HSM-resident private key.
     *
     * When Signature.sign() is called, the nCipherKM provider sends the data
     * to the nShield HSM, which performs the complete CKM_SHA384_RSA_PKCS
     * operation (hash + sign) inside the hardware boundary.
     *
     * @param privateKey HSM-resident private key (handle, not actual material)
     * @param document   raw document bytes
     * @return DER-encoded RSA signature
     */
    private static byte[] signDocument(PrivateKey privateKey, byte[] document) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
        sig.initSign(privateKey);
        sig.update(document);
        return sig.sign();
    }

    /**
     * Verifies a signature against a document using the public key.
     *
     * Verification can be done with ANY JCA provider — it doesn't require the HSM.
     * This means anyone with the public key can verify document authenticity.
     *
     * @param publicKey the signer's public key
     * @param document  the original document bytes
     * @param signature the signature to verify
     * @return true if the signature is valid
     */
    private static boolean verifySignature(PublicKey publicKey, byte[] document,
            byte[] signature) throws Exception {
        // Deliberately use the default provider for verification to demonstrate
        // that verification is HSM-independent
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(document);
        return sig.verify(signature);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Certificate Generation (self-signed, for KeyStore requirements)
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Generates a self-signed X.509v3 certificate for the signing key.
     *
     * This is needed because the JCE KeyStore API requires a certificate chain
     * when storing a private key. In a real deployment, you'd use a proper CA
     * to issue the signing certificate (e.g., your HSM-Backed CA).
     *
     * This implementation builds the DER-encoded TBS certificate structure manually
     * using only standard Java APIs (no sun.security.x509 internals, no Bouncy
     * Castle).
     * The signature is performed on the HSM via the nCipherKM provider.
     */
    private static Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
        var issuer = new X500Principal(
                "CN=HSM Document Signer, O=HSM-Backed-CA Demo, C=US");
        var notBefore = new Date();
        var notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000); // 1 year
        var serial = new BigInteger(64, new SecureRandom());

        // ── Build TBS (To-Be-Signed) Certificate in DER ────────────────
        byte[] tbs = buildTbsCertificate(serial, issuer, notBefore, notAfter, keyPair.getPublic());

        // ── Sign the TBS on the HSM ────────────────────────────────────
        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
        signer.initSign(keyPair.getPrivate());
        signer.update(tbs);
        byte[] signatureBytes = signer.sign();

        // ── Build the full X.509 Certificate (TBS + SigAlg + Signature) ─
        byte[] certDer = buildX509Certificate(tbs, signatureBytes);

        // ── Parse back through CertificateFactory for a proper X509Certificate ─
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certDer));

        // Verify our own certificate as a sanity check
        cert.verify(keyPair.getPublic());

        System.out.println("[+] Self-signed certificate generated:");
        System.out.println("    Subject: " + issuer.getName());
        System.out.println("    Serial:  " + serial);
        System.out.println("    Valid:   " + notBefore + " to " + notAfter);
        System.out.println("    SigAlg:  " + SIGNATURE_ALGORITHM);

        return cert;
    }

    // ──────────────────────────────────────────────────────────────────────
    // DER / ASN.1 Certificate Builder (no internal JDK APIs needed)
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Builds a DER-encoded TBSCertificate structure (RFC 5280 Section 4.1.2).
     *
     * TBSCertificate ::= SEQUENCE {
     * version [0] EXPLICIT INTEGER DEFAULT v1,
     * serialNumber INTEGER,
     * signature AlgorithmIdentifier,
     * issuer Name,
     * validity Validity,
     * subject Name,
     * subjectPublicKeyInfo SubjectPublicKeyInfo,
     * }
     */
    private static byte[] buildTbsCertificate(BigInteger serial, X500Principal issuer,
            Date notBefore, Date notAfter,
            PublicKey publicKey) throws Exception {
        ByteArrayOutputStream tbs = new ByteArrayOutputStream();

        // version [0] EXPLICIT INTEGER { v3(2) }
        tbs.write(derExplicit(0, derInteger(BigInteger.valueOf(2))));

        // serialNumber INTEGER
        tbs.write(derInteger(serial));

        // signature AlgorithmIdentifier (SHA384withRSA = 1.2.840.113549.1.1.12)
        tbs.write(derSignatureAlgorithm());

        // issuer Name (DER-encoded X.500 name)
        tbs.write(issuer.getEncoded());

        // validity Validity { notBefore, notAfter }
        ByteArrayOutputStream validity = new ByteArrayOutputStream();
        validity.write(derUtcTime(notBefore));
        validity.write(derUtcTime(notAfter));
        tbs.write(derSequence(validity.toByteArray()));

        // subject Name (same as issuer for self-signed)
        tbs.write(issuer.getEncoded());

        // subjectPublicKeyInfo (from the public key's X.509 encoding)
        tbs.write(publicKey.getEncoded());

        return derSequence(tbs.toByteArray());
    }

    /**
     * Builds the full X.509 Certificate DER structure:
     *
     * Certificate ::= SEQUENCE {
     * tbsCertificate TBSCertificate,
     * signatureAlgorithm AlgorithmIdentifier,
     * signatureValue BIT STRING
     * }
     */
    private static byte[] buildX509Certificate(byte[] tbs, byte[] signature) throws Exception {
        ByteArrayOutputStream cert = new ByteArrayOutputStream();
        cert.write(tbs);
        cert.write(derSignatureAlgorithm());
        cert.write(derBitString(signature));
        return derSequence(cert.toByteArray());
    }

    /** SHA384withRSA AlgorithmIdentifier: OID 1.2.840.113549.1.1.12, NULL params */
    private static byte[] derSignatureAlgorithm() throws Exception {
        // OID 1.2.840.113549.1.1.12 (sha384WithRSAEncryption)
        byte[] oid = new byte[] {
                0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7,
                0x0d, 0x01, 0x01, 0x0c
        };
        byte[] nullParam = new byte[] { 0x05, 0x00 };
        ByteArrayOutputStream algId = new ByteArrayOutputStream();
        algId.write(oid);
        algId.write(nullParam);
        return derSequence(algId.toByteArray());
    }

    // ── DER Primitives ──────────────────────────────────────────────────

    private static byte[] derSequence(byte[] content) {
        return derTag((byte) 0x30, content);
    }

    private static byte[] derInteger(BigInteger value) {
        byte[] encoded = value.toByteArray();
        return derTag((byte) 0x02, encoded);
    }

    private static byte[] derBitString(byte[] content) {
        // BIT STRING: first byte is the number of unused bits (0)
        byte[] withPad = new byte[content.length + 1];
        withPad[0] = 0x00;
        System.arraycopy(content, 0, withPad, 1, content.length);
        return derTag((byte) 0x03, withPad);
    }

    private static byte[] derExplicit(int tagNumber, byte[] content) {
        byte tag = (byte) (0xa0 | tagNumber);
        return derTag(tag, content);
    }

    @SuppressWarnings("deprecation")
    private static byte[] derUtcTime(Date date) {
        // UTCTime format: YYMMDDHHmmSSZ (for dates before 2050)
        var utc = new java.text.SimpleDateFormat("yyMMddHHmmss'Z'");
        utc.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        byte[] timeBytes = utc.format(date).getBytes(StandardCharsets.US_ASCII);
        return derTag((byte) 0x17, timeBytes);
    }

    private static byte[] derTag(byte tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeDerLength(out, content.length);
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write(length >> 8);
            out.write(length & 0xff);
        } else {
            out.write(0x83);
            out.write(length >> 16);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Utilities
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Creates a sample document to sign. In production, this would be
     * an actual file, API payload, or certificate TBS data.
     */
    private static byte[] createSampleDocument() {
        String doc = """
                ═══════════════════════════════════════
                DOCUMENT SIGNING DEMONSTRATION
                ═══════════════════════════════════════

                This document is digitally signed using
                an RSA-4096 key stored inside an Entrust
                nShield 5c Hardware Security Module.

                The private key NEVER leaves the HSM
                boundary. The signature was computed
                entirely within the FIPS 140-3 Level 3
                certified hardware.

                Date: %s
                Signer: HSM-Backed Document Signing Service
                Algorithm: SHA384withRSA
                Key Size: 4096-bit RSA
                ═══════════════════════════════════════
                """.formatted(new Date());
        return doc.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Gets the KeyStore passphrase. For module-protected keys with
     * ignorePassphrase=true, the passphrase is irrelevant but still required
     * by the API.
     */
    private static char[] getPassphrase() {
        String protect = System.getProperty("protect", "module");
        if ("module".equals(protect) && "true".equals(System.getProperty("ignorePassphrase"))) {
            // Module-protected with passphrase ignored — use a dummy
            return "unused".toCharArray();
        }

        // For OCS-protected keys, the passphrase must match the OCS card passphrase
        if (System.console() != null) {
            return System.console().readPassword("[?] Enter OCS passphrase: ");
        } else {
            // Fallback for IDEs that don't support Console
            System.out.print("[?] Enter OCS passphrase: ");
            try (var reader = new BufferedReader(new InputStreamReader(System.in))) {
                String line = reader.readLine();
                return line != null ? line.toCharArray() : new char[0];
            } catch (IOException e) {
                return new char[0];
            }
        }
    }

    /**
     * Benchmark signing throughput — measures how fast the HSM can sign
     * documents in sequence.
     */
    private static void benchmarkSigning(PrivateKey privateKey, int count) throws Exception {
        byte[][] docs = new byte[count][];
        for (int i = 0; i < count; i++) {
            docs[i] = ("Benchmark document #" + i + " -- " + new Date()).getBytes(StandardCharsets.UTF_8);
        }

        long start = System.nanoTime();
        for (int i = 0; i < count; i++) {
            signDocument(privateKey, docs[i]);
        }
        long totalMs = (System.nanoTime() - start) / 1_000_000;

        System.out.printf("    %d documents signed in %d ms (%.1f ms/doc, %.1f docs/sec)%n",
                count, totalMs,
                (double) totalMs / count,
                count * 1000.0 / totalMs);
    }

    /**
     * Exports the public key in PEM format so external systems can verify
     * signatures without needing HSM access.
     */
    private static void exportPublicKey(PublicKey publicKey) throws Exception {
        String pemFile = "document-signer-public.pem";
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKey.getEncoded());
        String pem = "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";

        Files.writeString(Path.of(pemFile), pem, StandardCharsets.UTF_8);
        System.out.println("\n[+] Public key exported: " + pemFile);
        System.out.println("    External systems can verify signatures using this key");
        System.out.println("    (no HSM access needed for verification).");
    }
}
