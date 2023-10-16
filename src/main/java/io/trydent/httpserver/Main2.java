package io.trydent.httpserver;

import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.util.resource.ResourceFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import javax.net.ssl.TrustManagerFactory;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public enum Main2 {
  Instance;

  private final String path = "io/trydent/httpserver/";
  private final String indexHtml = STR. "\{ path }web/index.html" ;
  private final String caBundle = STR. "\{ path }cert/ca_bundle.crt" ;
  private final String certificate = STR. "\{ path }cert/certificate.crt" ;
  private final String alpenflowIO = STR. "\{ path }cert/alpenflow.io.crt" ;
  private final String privateKey = STR. "\{ path }cert/private.key" ;
  private final String privatePem = STR. "\{ path }cert/private.pem" ;
  private final String accountPem = STR. "\{ path }cert/account.alpenflow.io.pem" ;
  private final String domainPem = STR. "\{ path }cert/domain.alpenflow.io.pem" ;
  private final String domainCrt = STR. "\{ path }cert/domain.alpenflow.io.crt" ;
  private final String domainCsr = STR. "\{ path }cert/domain.alpenflow.io.csr" ;


  public static void main(String[] args) throws Exception {
    System.setProperty("jdk.tls.server.disableExtensions", "false");
    System.setProperty("javax.net.debug", "all");
    System.setProperty("https.protocols", "TLSv1.3");
    System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
    System.setProperty("com.sun.net.ssl.enableECC", "true");
    System.setProperty("jsse.enableSNIExtension", "true");
//    Security.addProvider(new BouncyCastleProvider());


    final var caCertificate = Main.Instance.fetchCertificate(Instance.certificate);
    final var caBundle = Main.Instance.fetchCertificate(Instance.caBundle);

    //final var privateKey = Main.Instance.fetchPrivatePem();

    final var trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, "password".toCharArray());
    trustStore.setCertificateEntry("alpenflow.io", caCertificate);
    //trustStore.setCertificateEntry("ca-bundle", caBundle);
    //trustStore.setKeyEntry("private-key", privateKey, "password".toCharArray(), new Certificate[]{caCertificate, caBundle});

    final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
/*

    final var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, "password".toCharArray());
    //keyStore.setCertificateEntry("alpenflow.io", certs[0]);
    keyStore.setKeyEntry("alpenflow.io", privateKey, "password".toCharArray(), certs);

*/
    var threadPool = new QueuedThreadPool();
    threadPool.setName("server");

// Create a Server instance.
    var server = new Server(threadPool);

// The HTTP configuration object.
    var httpConfig = new HttpConfiguration();
// Add the SecureRequestCustomizer because TLS is used.
    httpConfig.addCustomizer(new SecureRequestCustomizer());

// The ConnectionFactory for HTTP/1.1.
    var http11 = new HttpConnectionFactory(httpConfig);

// Configure the SslContextFactory with the keyStore information.
    var sslContextFactory = new SslContextFactory.Server();
    sslContextFactory.setTrustStore(trustStore);
    sslContextFactory.setTrustStorePassword("password");
    try (
      final var keyResource = Main.class.getClassLoader().getResourceAsStream(Instance.privateKey);
      final var bundleResource = Main.class.getClassLoader().getResourceAsStream(Instance.caBundle)
    ) {
      sslContextFactory.setKeyStore(PemReader.loadKeyStore(bundleResource, keyResource, Optional.empty()));
      sslContextFactory.setKeyStorePassword("password");
    }
// The ConnectionFactory for TLS.
    var tls = new SslConnectionFactory(sslContextFactory, http11.getProtocol());

// Create a ServerConnector to accept connections from clients.
    var connector = new ServerConnector(server, tls, http11);
    connector.setPort(8443);

// Add the Connector to the Server
    server.addConnector(connector);

    var indexResource = Main.class.getClassLoader().getResource(Instance.indexHtml);
    var path = Path.of(requireNonNull(indexResource).toURI());

    var handler = new ResourceHandler();

// Configure the directory where static resources are located.
    handler.setBaseResource(ResourceFactory.of(handler).newResource(path.getParent()));
// Configure directory listing.
    handler.setDirAllowed(false);
// Configure welcome files.
    handler.setWelcomeFiles(List.of("index.html"));
// Configure whether to accept range requests.
    handler.setAcceptRanges(true);

// Link the context to the server.
    server.setHandler(handler);

// Start the Server to start accepting connections from clients.
    server.start();
  }
}
