package io.trydent.httpserver;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpHandlers;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.SimpleFileServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.concurrent.Executors;

import static java.util.Objects.requireNonNull;

interface Main {
  static void main(String... args) {
    try {
      var httpServer = HttpServer.create(new InetSocketAddress(8080), Integer.MAX_VALUE);
      httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
      System.out.println(Main.class.getClassLoader().getResource("web/index.html").toExternalForm());
      httpServer.createContext("/", SimpleFileServer.createFileHandler(Path.of(requireNonNull(Main.class.getClassLoader().getResource("web")).toURI())));
      httpServer.start();
      System.out.println("Http Server started on port 8080");
    } catch (IOException | URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }
}
