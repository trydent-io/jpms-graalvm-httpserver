package io.trydent.httpserver;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.SimpleFileServer;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

enum Main {
  Instance;

  private final String path = "io/trydent/httpserver/";
  private final String indexHtml = STR. "\{ path }web/index.html" ;
  private final String accountPem = STR. "\{ path }cert/account.alpenflow.io.pem" ;
  private final String domainPem = STR. "\{ path }cert/domain.alpenflow.io.pem" ;
  private final String domainCrt = STR. "\{ path }cert/domain.alpenflow.io.crt" ;
  private final String domainCsr = STR. "\{ path }cert/domain.alpenflow.io.csr" ;

  public ECPrivateKey privateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    try (final var pemResource = Main.class.getClassLoader().getResourceAsStream(Instance.domainPem)) {
      final var key = new String(requireNonNull(pemResource).readAllBytes());

      System.out.println(key);

      final var privateKeyPEM = key
        .replace("-----BEGIN EC PRIVATE KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END EC PRIVATE KEY-----", "");

      final var decoded = Base64.getDecoder().decode(privateKeyPEM.getBytes());

      final var params = ECNamedCurveTable.getParameterSpec("secp256k1");
      final var curve = params.getCurve();
      
      return (ECPrivateKey) KeyFactory
        .getInstance("EC")
        .generatePrivate(new ECPrivateKeySpec(decoded));
    }
  }

  public void setup() throws IOException, URISyntaxException, NoSuchAlgorithmException, InvalidKeySpecException {
    System.out.println(STR. "\{ privateKey().getEncoded() }" );

    var httpServer = HttpServer.create(new InetSocketAddress(8080), Integer.MAX_VALUE);
    var indexResource = Main.class.getClassLoader().getResource(Instance.indexHtml);
    var path = Path.of(requireNonNull(indexResource).toURI());
    System.out.println(path.toUri());
    httpServer.createContext("/", SimpleFileServer.createFileHandler(path.getParent()));
    httpServer.start();
    System.out.println("Http Server started on port 8080");

  }

  public static void main(String... args) throws IOException, URISyntaxException, NoSuchAlgorithmException, InvalidKeySpecException {
    Instance.setup();
  }
}
