package io.trydent.httpserver;


import io.trydent.httpserver.cert.DerInputStream;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.CharBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static javax.crypto.Cipher.DECRYPT_MODE;

public final class PemReader {
  // Header
  // Base64 text
  private static final Pattern CERT_PATTERN = Pattern.compile(
    "-+BEGIN\\s+.*CERTIFICATE[^-]*-+(?:\\s|\\r|\\n)+([a-z0-9+/=\\r\\n]+)-+END\\s+.*CERTIFICATE[^-]*-+",            // Footer
    CASE_INSENSITIVE);

  // Header
  // Base64 text
  private static final Pattern KEY_PATTERN = Pattern.compile(
    "-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+([a-z0-9+/=\\r\\n]+)-+END\\s+.*PRIVATE\\s+KEY[^-]*-+",            // Footer
    CASE_INSENSITIVE);

  private PemReader() {}

  public static KeyStore loadTrustStore(InputStream certificateChainFile) throws IOException, GeneralSecurityException {
    var keyStore = KeyStore.getInstance("JKS");
    keyStore.load(null, null);

    var certificateChain = readCertificateChain(certificateChainFile);
    for (var certificate : certificateChain) {
      var principal = certificate.getSubjectX500Principal();
      keyStore.setCertificateEntry(principal.getName("RFC2253"), certificate);
    }
    return keyStore;
  }

  public static KeyStore loadKeyStore(InputStream certificateChainFile, InputStream privateKeyFile, Optional<String> keyPassword)
    throws IOException, GeneralSecurityException {
    var encodedKeySpec = readPrivateKey(privateKeyFile, keyPassword);
    PrivateKey key;
    try {
      var keyFactory = KeyFactory.getInstance("RSA");
      key = keyFactory.generatePrivate(encodedKeySpec);
    } catch (InvalidKeySpecException ignore) {
      var keyFactory = KeyFactory.getInstance("DSA");
      key = keyFactory.generatePrivate(encodedKeySpec);
    }

    var certificateChain = readCertificateChain(certificateChainFile);
    if (certificateChain.isEmpty()) {
      throw new CertificateException("Certificate file does not contain any certificates: " + certificateChainFile);
    }

    var keyStore = KeyStore.getInstance("JKS");
    keyStore.load(null, null);
    keyStore.setKeyEntry("key", key, keyPassword.orElse("").toCharArray(), certificateChain.stream().toArray(Certificate[]::new));
    return keyStore;
  }

  private static List<X509Certificate> readCertificateChain(InputStream certificateChainFile) throws IOException, GeneralSecurityException {
    var contents = readFile(certificateChainFile);

    var matcher = CERT_PATTERN.matcher(contents);
    var certificateFactory = CertificateFactory.getInstance("X.509");
    List<X509Certificate> certificates = new ArrayList<>();

    var start = 0;
    while (matcher.find(start)) {
      var buffer = base64Decode(matcher.group(1));
      certificates.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(buffer)));
      start = matcher.end();
    }

    return certificates;
  }

  private static EncodedKeySpec readPrivateKey(InputStream keyFile, Optional<String> keyPassword) throws IOException, GeneralSecurityException {
    var bytes = keyFile.readAllBytes();
    var privateKeyPlain = new String(bytes, UTF_8);
    System.out.println(privateKeyPlain);

    var matcher = KEY_PATTERN.matcher(privateKeyPlain);
    if (!matcher.find()) {
      throw new KeyStoreException("found no private key: " + keyFile);
    }
    System.out.println("\n" + matcher.group(1));
    var encodedKey = Base64.getMimeDecoder().decode(matcher.group(1).getBytes(UTF_8));

    if (!keyPassword.isPresent()) {
      return new X509EncodedKeySpec(encodedKey);
      //return new PKCS8EncodedKeySpec(encodedKey);
    }

    var encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encodedKey);
    var keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
    var secretKey = keyFactory.generateSecret(new PBEKeySpec(keyPassword.get().toCharArray()));

    var cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
    cipher.init(DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.getAlgParameters());

    return encryptedPrivateKeyInfo.getKeySpec(cipher);
  }

  private static byte[] base64Decode(String base64) {
    return Base64.getMimeDecoder().decode(base64.getBytes(US_ASCII));
  }

  public static PrivateKey pkcs1PrivateKey(String file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    try (final var input = Main.class.getClassLoader().getResourceAsStream(file)) {
      var content = new String(requireNonNull(input).readAllBytes())
        .replaceAll("\\n", "")
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "");

      System.out.println(content);

      var bytes = Base64.getMimeDecoder().decode(content);

      var derReader = new DerInputStream(bytes);
      var seq = derReader.getSequence(0);
      // skip version seq[0];
      var modulus = seq[1].getBigInteger();
      var publicExp = seq[2].getBigInteger();
      var privateExp = seq[3].getBigInteger();
      var prime1 = seq[4].getBigInteger();
      var prime2 = seq[5].getBigInteger();
      var exp1 = seq[6].getBigInteger();
      var exp2 = seq[7].getBigInteger();
      var crtCoef = seq[8].getBigInteger();

      return KeyFactory.getInstance("RSA")
        .generatePrivate(new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef));
    }
  }

/*  private static String readFile(File file) throws IOException {
    try (Reader reader = new InputStreamReader(new FileInputStream(file), US_ASCII)) {
      var stringBuilder = new StringBuilder();

      var buffer = CharBuffer.allocate(2048);
      while (reader.read(buffer) != -1) {
        buffer.flip();
        stringBuilder.append(buffer);
        buffer.clear();
      }
      return stringBuilder.toString();
    }
  }*/

  private static String readFile(InputStream input) throws IOException {
    try (Reader reader = new InputStreamReader(input, US_ASCII)) {
      var stringBuilder = new StringBuilder();

      var buffer = CharBuffer.allocate(2048);
      while (reader.read(buffer) != -1) {
        buffer.flip();
        stringBuilder.append(buffer);
        buffer.clear();
      }
      return stringBuilder.toString();
    }
  }
}
