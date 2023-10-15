package io.trydent.httpserver;

import com.sun.net.httpserver.*;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
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
import java.util.concurrent.Executors;

import static io.trydent.httpserver.ConsoleLog.CONSOLE_LOG;
import static java.lang.System.out;
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

  public PrivateKey fetchPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    try (
      final var keyResource = Main.class.getClassLoader().getResourceAsStream(Instance.privatePem);
    ) {
      return KeyFactory.getInstance("RSA")
        .generatePrivate(new PKCS8EncodedKeySpec(requireNonNull(keyResource).readAllBytes()));
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
//    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    //System.setProperty("javax.net.debug", "all");
//    System.setProperty("jdk.tls.server.disableExtensions", "true");
    System.setProperty("jdk.tls.client.cipherSuites", "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
    System.setProperty("jdk.tls.server.cipherSuites", "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV");

    final Certificate caCertificate = null;
    final Certificate caBundle = null;
    final PrivateKey privateKey = null;

    final var trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("ca-certificate", caCertificate);
    trustStore.setCertificateEntry("ca-certificate-bundle", caBundle);
    trustStore.setKeyEntry("private-key", privateKey, "password".toCharArray(), new Certificate[]{caCertificate, caBundle});

    final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);

    final var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setCertificateEntry("ca-certificate", caCertificate);
    keyStore.setCertificateEntry("ca-certificate-bundle", caBundle);
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
      new InetSocketAddress(8080),
      10,
      "/",
      exchange -> HttpHandlers.of(302, Headers.of(Map.of("Location", List.of("https://alpenflow.io"))), "").handle(exchange),
      CONSOLE_LOG
    );
    httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    //httpServer.start();

    var fileHandler = SimpleFileServer.createFileHandler(path.getParent());
    var httpsServer = HttpsServer.create(new InetSocketAddress(8448), 10, "/", fileHandler, CONSOLE_LOG);
    httpsServer.setHttpsConfigurator(new HttpsConfigurator(tls) {
      @Override
      public void configure(HttpsParameters params) {
        var sslContext = getSSLContext();
        var sslEngine = sslContext.createSSLEngine();
        params.setNeedClientAuth(false);
        params.setWantClientAuth(false);
        params.setCipherSuites(sslEngine.getEnabledCipherSuites());
        params.setProtocols(sslEngine.getEnabledProtocols());

        var parameters = sslContext.getDefaultSSLParameters();
        parameters.setEnableRetransmissions(true);
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        params.setSSLParameters(parameters);

      }
    });
    httpsServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    //httpsServer.start();

    var threadPool = new QueuedThreadPool();
    threadPool.setName("server");

    var jetty = new Server(threadPool);


    var httpConfig = new HttpConfiguration();
// Add the SecureRequestCustomizer because TLS is used.
    httpConfig.addCustomizer(new SecureRequestCustomizer());

    var http11 = new HttpConnectionFactory(httpConfig);

// Configure the SslContextFactory with the keyStore information.
    var sslContextFactory = new SslContextFactory.Server();
    sslContextFactory.setSslContext(tls);

    var tlsFactory = new SslConnectionFactory(sslContextFactory, http11.getProtocol());

    // Create a ServerConnector to accept connections from clients.
    var connector = new ServerConnector(jetty, tlsFactory, http11);
    connector.setPort(8443);

// Add the Connector to the Server
    jetty.addConnector(connector);


// Set a simple Handler to handle requests/responses.
    jetty.setHandler(new Handler.Abstract() {
      @Override
      public boolean handle(org.eclipse.jetty.server.Request request, Response response, Callback callback) {
        response.setStatus(200);
        callback.succeeded();
        return true;
      }
    });

// Start the Server to start accepting connections from clients.
    jetty.start();
    jetty.join();

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
