package io.trydent.httpserver;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.SimpleFileServer;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.file.Path;

import static java.util.Objects.requireNonNull;

enum Main {
  Instance;

  private final String path = "io/trydent/httpserver/";
  private final String indexHtml = STR. "\{ path }web/index.html" ;
  private final String certPem = STR. "\{ path }cert/domain.alpenflow.io.pem" ;

  public static void main(String... args) throws IOException, URISyntaxException {
    var pemResource = Main.class.getClassLoader().getResource(Instance.certPem);
    try (
      final var fileReader = new FileReader(new File(requireNonNull(pemResource).toURI()));
      final var pemReader = new PemReader(fileReader)
    ) {

    }

    var httpServer = HttpServer.create(new InetSocketAddress(8080), Integer.MAX_VALUE);
    var indexResource = Main.class.getClassLoader().getResource(Instance.indexHtml);
    var path = Path.of(requireNonNull(indexResource).toURI());
    System.out.println(path.toUri());
    httpServer.createContext("/", SimpleFileServer.createFileHandler(path.getParent()));
    httpServer.start();
    System.out.println("Http Server started on port 8080");
  }
}
