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
import java.security.interfaces.ECPrivateKey;
import java.util.Optional;
import java.util.concurrent.Executors;

import static java.util.Objects.requireNonNull;

enum Main {
  Instance;

  private final String path = "io/trydent/httpserver/";
  private final String indexHtml = STR. "\{ path }web/index.html" ;
  private final String accountPem = STR. "\{ path }cert/account.alpenflow.io.pem" ;
  private final String domainPem = STR. "\{ path }cert/domain.alpenflow.io.pem" ;
  private final String domainCrt = STR. "\{ path }cert/domain.alpenflow.io.crt" ;
  private final String domainCsr = STR. "\{ path }cert/domain.alpenflow.io.csr" ;

  public Optional<ECPrivateKey> privateKey() throws IOException {
    try (
      final var pemResource = Main.class.getClassLoader().getResourceAsStream(Instance.domainPem);
      final var inputReader = new InputStreamReader(requireNonNull(pemResource));
      final var pemParser = new PEMParser(inputReader)
    ) {
      final var parsedPem = pemParser.readObject();

      if (parsedPem instanceof PEMKeyPair keyPair) {
        final var privateKey = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(keyPair.getPrivateKeyInfo());
        return privateKey instanceof ECPrivateKey it ? Optional.of(it) : Optional.empty();
      }
    }
    return Optional.empty();
  }

  public Optional<Certificate> caCertificate() throws IOException, CertificateException {
    try (
      final var crtResource = Main.class.getClassLoader().getResourceAsStream(Instance.domainCrt);
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

  public void setup() throws IOException, URISyntaxException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {
    Security.insertProviderAt(new BouncyCastleProvider(), 1);

    final var caCertificate = caCertificate().orElseThrow();
    final var privateKey = privateKey().orElseThrow();

    final var caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    caKeyStore.load(null, null);
    caKeyStore.setCertificateEntry("ca-certificate", caCertificate);

    final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(caKeyStore);

    final var clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    clientKeyStore.load(null, null);
    clientKeyStore.setCertificateEntry("certificate", caCertificate);
    clientKeyStore.setKeyEntry("private-key", privateKey, "password".toCharArray(), new Certificate[]{caCertificate});

    var keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(clientKeyStore, "password".toCharArray());

    final var tls = SSLContext.getInstance("TLSv1.3");
    tls.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

    var indexResource = Main.class.getClassLoader().getResource(Instance.indexHtml);
    var path = Path.of(requireNonNull(indexResource).toURI());

    var httpServer = HttpServer.create(new InetSocketAddress(8080), Integer.MAX_VALUE);
    httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    httpServer.createContext("/", SimpleFileServer.createFileHandler(path.getParent()));
    httpServer.start();
    System.out.println("Http Server started on port 80");

    var httpsServer = HttpsServer.create(new InetSocketAddress(8443), Integer.MAX_VALUE);
    System.out.println(path.toUri());
    httpsServer.setHttpsConfigurator(new HttpsConfigurator(tls) {
      @Override
      public void configure(HttpsParameters params) {
        var sslContext = tls; // getSSLContext();
        var sslEngine = sslContext.createSSLEngine();
        params.setNeedClientAuth(false);
        params.setCipherSuites(sslEngine.getEnabledCipherSuites());
        params.setProtocols(sslEngine.getEnabledProtocols());
        params.setSSLParameters(sslContext.getDefaultSSLParameters());
      }
    });
    httpsServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    httpsServer.createContext("/", SimpleFileServer.createFileHandler(path.getParent()));
    httpsServer.start();
    System.out.println("Https Server started on port 443");
  }

  public static void main(String... args) throws IOException, URISyntaxException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException, KeyManagementException {
    Instance.setup();
  }
}
