package io.trydent.httpserver;

import com.google.common.jimfs.Jimfs;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.SimpleFileServer;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.file.Path;

import static java.util.Objects.requireNonNull;

class Main {
  private static final File USER_KEY_FILE = new File("user.key");
  private static final File DOMAIN_KEY_FILE = new File("domain.key");
  private static final File DOMAIN_CSR_FILE = new File("domain.csr");
  private static final File DOMAIN_CHAIN_FILE = new File("domain-chain.crt");

  private static final ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP;

  private static final int KEY_SIZE = 2048;

  public static void main(String... args) throws IOException, URISyntaxException {
    try (final var fileSystem = Jimfs.newFileSystem()) {
      var userKey = fileSystem.getPath("user.key").toFile();
      var domainKey = fileSystem.getPath("domain.key").toFile();
      try (
          final var fileReader = new FileReader(userKey);
          final var parser = new PEMParser(fileReader)
      ) {
        var keyPair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) parser.readObject());
      }

      var httpServer = HttpServer.create(new InetSocketAddress(8080), Integer.MAX_VALUE);
      var resource = Main.class.getClassLoader().getResource("web/index.html");
      var path = Path.of(requireNonNull(resource).toURI());
      System.out.println(path.toUri());
      httpServer.createContext("/", SimpleFileServer.createFileHandler(path.getParent()));
      httpServer.start();
      System.out.println("Http Server started on port 8080");
    }
  }

  private enum ChallengeType {HTTP, DNS}
}
