package io.trydent.httpserver;

import com.sun.net.httpserver.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;

import static io.trydent.httpserver.ConsoleLog.CONSOLE_LOG;
import static java.lang.System.in;
import static java.lang.System.out;
import static java.util.Objects.requireNonNull;

enum Main {
  Instance;

  private final String path = "io/trydent/httpserver/";
  private final String indexHtml = STR. "\{ path }web/index.html" ;
  private final String caBundle = STR. "\{ path }cert/ca_bundle.crt" ;
  private final String certificate = STR. "\{ path }cert/certificate.crt" ;
  private final String privateKey = STR. "\{ path }cert/private.key" ;
  private final String accountPem = STR. "\{ path }cert/account.alpenflow.io.pem" ;
  private final String domainPem = STR. "\{ path }cert/domain.alpenflow.io.pem" ;
  private final String domainCrt = STR. "\{ path }cert/domain.alpenflow.io.crt" ;
  private final String domainCsr = STR. "\{ path }cert/domain.alpenflow.io.csr" ;

  public static void main(String... args) throws IOException, URISyntaxException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException, KeyManagementException, NoSuchProviderException {
    Instance.setup();
  }

  public Optional<PrivateKey> privateKey() throws IOException {
    try (
      final var pemResource = Main.class.getClassLoader().getResourceAsStream(Instance.privateKey);
      final var inputReader = new InputStreamReader(requireNonNull(pemResource));
      final var pemParser = new PEMParser(inputReader)
    ) {
      final var parsedPem = pemParser.readObject();

      if (parsedPem instanceof PEMKeyPair keyPair) {
        final var privateKey = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(keyPair.getPrivateKeyInfo());
        return privateKey instanceof PrivateKey it ? Optional.of(it) : Optional.empty();
      }
    }
    return Optional.empty();
  }

  public void caBundle() throws IOException, CertificateException, NoSuchProviderException {
    try (final var caBundleResource = Main.class.getClassLoader().getResourceAsStream(Instance.certificate)) {
      var factory = CertificateFactory.getInstance("X.509", "BC");
      while (requireNonNull(caBundleResource).available() > 0) {
        var index = 0;
        for (final var certificate : factory.generateCertificates(caBundleResource)) {
          out.println(STR."Certificate Bundle \{index}");
        }
      }
    }
  }

  public void certificates(String certificatePath) throws IOException, CertificateException, NoSuchProviderException {
    try (final var certificateResource = Main.class.getClassLoader().getResourceAsStream(certificatePath)) {
      var factory = CertificateFactory.getInstance("X.509", "BC");
      var input = requireNonNull(certificateResource);
      out.println(STR."Starting: \{input.available()}");
      while (input.available() > 0) {
        var index = 0;
        for (final var certificate : factory.generateCertificates(certificateResource)) {
          out.println(STR."Certificate \{index++} remaining: \{input.available()}");
        }
      }
    }
  }

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

  public void setup() throws IOException, URISyntaxException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException, NoSuchProviderException {
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    System.setProperty("jdk.tls.client.cipherSuites", "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
    System.setProperty("jdk.tls.server.cipherSuites", "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV");


    certificates(Instance.certificate);
    certificates(Instance.caBundle);
    final var caCertificate = caCertificate(Instance.certificate).orElseThrow();
    final var caBundle = caCertificate(Instance.caBundle).orElseThrow();
    final var privateKey = privateKey().orElseThrow();

    final var caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    caKeyStore.load(null, null);
    caKeyStore.setCertificateEntry("ca-certificate", caCertificate);
    caKeyStore.setCertificateEntry("ca-certificate-bundle", caBundle);

    final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(caKeyStore);

    final var clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    clientKeyStore.load(null, null);
    clientKeyStore.setCertificateEntry("certificate", caCertificate);
    clientKeyStore.setCertificateEntry("ca-certificate-bundle", caBundle);
    clientKeyStore.setKeyEntry("private-key", privateKey, "password".toCharArray(), new Certificate[]{caCertificate, caBundle});

    var keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(clientKeyStore, "password".toCharArray());

    final var tls = SSLContext.getInstance("TLSv1.3");
    tls.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

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
        try {
          var sslContext = SSLContext.getDefault();
          var sslEngine = sslContext.createSSLEngine();
          params.setNeedClientAuth(false);
          params.setWantClientAuth(false);
          params.setCipherSuites(sslEngine.getEnabledCipherSuites());
          params.setProtocols(sslEngine.getEnabledProtocols());
          params.setSSLParameters(sslContext.getDefaultSSLParameters());

        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
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
