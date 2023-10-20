package io.trydent.httpserver;

import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;

import static io.trydent.httpserver.ConsoleLog.CONSOLE_LOG;
import static java.lang.System.out;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;

enum Main {
  Instance;

  private final String path = "io/trydent/httpserver/";
  private final String indexHtml = STR. "\{ path }web/index.html" ;
  private final String caBundle = STR. "\{ path }cert/ca_bundle.crt" ;
  private final String certificate = STR. "\{ path }cert/certificate.crt" ;
  private final String privateKey = STR. "\{ path }cert/private.key" ;
  private final String privatePem = STR. "\{ path }cert/private.pem" ;
  private final String accountPem = STR. "\{ path }cert/account.alpenflow.io.pem" ;
  private final String domainPem = STR. "\{ path }cert/domain.alpenflow.io.pem" ;
  private final String domainCrt = STR. "\{ path }cert/domain.alpenflow.io.crt" ;
  private final String domainCsr = STR. "\{ path }cert/domain.alpenflow.io.csr" ;

  public static void main(String... args) throws Exception {
    Instance.setup();
  }
/*
  public Optional<PrivateKey> privateKey() throws IOException {
    try (
      final var pemResource = Main.class.getClassLoader().getResourceAsStream(Instance.privateKey);
      final var inputReader = new InputStreamReader(requireNonNull(pemResource));
      final var pemParser = new PEMParser(inputReader)
    ) {
      final var parsedPem = pemParser.readObject();


      if (parsedPem instanceof PEMKeyPair keyPair) {
        final var privateKey = new JcaPEMKeyConverter().getPrivateKey(keyPair.getPrivateKeyInfo());
        return privateKey instanceof PrivateKey it ? Optional.of(it) : Optional.empty();
      }
    }
    return Optional.empty();
  }*/

  public PrivateKey fetchPrivatePem() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    try (
      final var keyResource = Main.class.getClassLoader().getResourceAsStream(Instance.privatePem);
    ) {
      return KeyFactory.getInstance("RSA")
        .generatePrivate(new PKCS8EncodedKeySpec(requireNonNull(keyResource).readAllBytes()));
    }
  }

  public KeyStore fetchKeyStore() throws IOException, GeneralSecurityException {
    try (
      final var keyResource = Main.class.getClassLoader().getResourceAsStream(Instance.privatePem);
      final var bundleResource = Main.class.getClassLoader().getResourceAsStream(Instance.caBundle)
    ) {
      return PemReader.loadKeyStore(bundleResource, keyResource, Optional.of("password"));
    }
  }

  public void caBundle() throws IOException, CertificateException, NoSuchProviderException {
    try (final var caBundleResource = Main.class.getClassLoader().getResourceAsStream(Instance.certificate)) {
      var factory = CertificateFactory.getInstance("X.509", "BC");
      while (requireNonNull(caBundleResource).available() > 0) {
        var index = 0;
        for (final var certificate : factory.generateCertificates(caBundleResource)) {
          out.println(STR. "Certificate Bundle \{ index }" );
        }
      }
    }
  }

  public Certificate fetchCertificate(String certificatePath) throws IOException, CertificateException {
    try (final var certificateResource = Main.class.getClassLoader().getResourceAsStream(certificatePath)) {
      return CertificateFactory.getInstance("X.509")
        .generateCertificate(requireNonNull(certificateResource));
    }
  }

  public Certificate[] fetchCertificates(String certificatePath) throws IOException, CertificateException {
    try (final var certificateResource = Main.class.getClassLoader().getResourceAsStream(certificatePath)) {
      return CertificateFactory.getInstance("X.509")
        .generateCertificates(requireNonNull(certificateResource))
        .toArray(Certificate[]::new);
    }
  }
/*

  public Optional<X509Certificate> caCertificate(String certificate) throws IOException, CertificateException {
    try (
      final var crtResource = Main.class.getClassLoader().getResourceAsStream(certificate);
      final var inputReader = new InputStreamReader(requireNonNull(crtResource));
      final var crtParser = new PEMParser(inputReader)
    ) {
      final var parsedCrt = crtParser.readObject();

      if (parsedCrt instanceof X509CertificateHolder holder) {
        return Optional.ofNullable(new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder));
      }
    }

    return Optional.empty();
  }
*/

  public void setup() throws Exception {
    System.setProperty("jdk.tls.server.disableExtensions", "false");
    //System.setProperty("javax.net.debug", "all");
//    System.setProperty("https.protocols", "TLSv1.3,TLSv1.2Hello");
//    System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "false");
    System.setProperty("com.sun.net.ssl.enableECC", "true");
    System.setProperty("jsse.enableSNIExtension", "true");
    System.setProperty("jdk.tls.ephemeralDHKeySize", "2048");
/*
    System.setProperty("jdk.tls.disabledAlgorithms", """
      SSLv2Hello, SSLv3, TLSv1, TLSv1.1, DES, DESede, RC4, MD5withRSA, DH keySize < 1024,
      EC keySize < 224, DES40_CBC, RC4_40,
      TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA,
      TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA,
      TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256,
      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA
      """);
*/
/*

    System.setProperty("jdk.tls.client.cipherSuites", "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
    System.setProperty("jdk.tls.server.cipherSuites", "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
*/

    final var caCertificate = fetchCertificate(Instance.certificate);
    final var caBundle = fetchCertificate(Instance.caBundle);
    final var privateKey = PemReader.pkcs1PrivateKey(Instance.privateKey);

    final var trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("alpenflow.io", caCertificate);

    final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);

    final var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry("private-key", privateKey, "password".toCharArray(), new Certificate[]{caCertificate, caBundle});

    var keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, "password".toCharArray());

    final var tls = SSLContext.getInstance("TLSv1.3");
    tls.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(tls.getSocketFactory());

    SSLContext.setDefault(tls);

    var indexResource = Main.class.getClassLoader().getResource(Instance.indexHtml);
    var path = Path.of(requireNonNull(indexResource).toURI());

    var httpServer = HttpServer.create(
      new InetSocketAddress(80),
      10,
      "/",
      exchange -> HttpHandlers.of(302, Headers.of(Map.of("Location", List.of("https://alpenflow.io"))), "").handle(exchange),
      CONSOLE_LOG
    );
    httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    httpServer.start();

    var fileHandler = SimpleFileServer.createFileHandler(path.getParent());
    var httpsServer = HttpsServer.create(new InetSocketAddress(443), 10, "/", fileHandler, CONSOLE_LOG);
    httpsServer.setHttpsConfigurator(new HttpsConfigurator(tls) {
      @Override
      public void configure(HttpsParameters params) {
        var sslContext = getSSLContext();
        var sslEngine = sslContext.createSSLEngine();
        var parameters = sslContext.getDefaultSSLParameters();
        parameters.setEnableRetransmissions(true);
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setApplicationProtocols(
          stream(sslEngine.getEnabledProtocols())
            .peek(it -> out.println(STR."Current App Protocol: \{it}"))
            //.filter(it -> !it.startsWith("SSL") && !it.startsWith("SSLv2") && !it.startsWith("SSLv2Hello") && !it.startsWith("SSLv3"))
            //.peek(it -> out.println(STR."App Protocol: \{it}"))
            .toArray(String[]::new)
        );
        //parameters.setUseCipherSuitesOrder(true);
        //parameters.setServerNames(List.of(new SNIHostName(sslEngine.getPeerHost().getBytes(US_ASCII))));
        params.setSSLParameters(parameters);
        params.setNeedClientAuth(false);
        params.setWantClientAuth(false);
        params.setCipherSuites(
          stream(sslEngine.getEnabledCipherSuites())
            //.filter(it -> !it.startsWith("TLS_RSA_") && !it.startsWith("SSL") && !it.contains("_NULL_") && !it.contains("_anon_"))
            //.filter(it -> it.endsWith("AES_256_GCM_SHA384") || it.endsWith("AES_128_GCM_SHA256") || it.endsWith("CHACHA20_POLY1305_SHA256"))
            .peek(it -> out.println(STR."Cipher: \{it}"))
            .toArray(String[]::new)
        );
        params.setProtocols(
          stream(sslEngine.getEnabledProtocols())
            .peek(it -> out.println(STR."Current Protocol: \{it}"))
            //.filter(it -> !it.equals("SSL") && !it.equals("SSLv2") && !it.startsWith("SSLv2Hello") && !it.startsWith("SSLv3"))
            //.peek(it -> out.println(STR."Protocol: \{it}"))
            .toArray(String[]::new)
        );
      }
    });
    httpsServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    httpsServer.start();

    System.out.println("Https Server started on port 443");
  }
}

final class ConsoleLog extends Filter {
  static final ConsoleLog CONSOLE_LOG = new ConsoleLog();
  private static final DateTimeFormatter format = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  @Override
  public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
    out.println(STR. "[\{ LocalDateTime.now().format(format) }] \{ exchange.getRequestMethod() } \{ exchange.getRequestURI() } \{ exchange.getRemoteAddress() }" );
    chain.doFilter(exchange);
  }

  @Override
  public String description() {
    return "console-log";
  }
}
