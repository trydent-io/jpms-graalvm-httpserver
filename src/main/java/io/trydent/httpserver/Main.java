package io.trydent.httpserver;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.SimpleFileServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;

import static java.util.Objects.requireNonNull;

class Main {
  public static void main(String... args) {
    try {
      var httpServer = HttpServer.create(new InetSocketAddress(8080), Integer.MAX_VALUE);
      var resource = Main.class.getClassLoader().getResource("web/index.html");
      System.out.println(new String(resource.openStream().readAllBytes()));
      var path = Path.of(Main.class.getClassLoader().getResource("web/index.html").toURI());
      System.out.println(path.toUri());
      httpServer.createContext("/", SimpleFileServer.createFileHandler(path.getParent()));
      httpServer.start();
      System.out.println("Http Server started on port 8080");
    } catch (IOException | URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }
}
