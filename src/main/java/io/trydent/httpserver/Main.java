package io.trydent.httpserver;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpHandlers;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

interface Main {
  static void main(String... args) {
    try {
      var httpServer = HttpServer.create(new InetSocketAddress(8080), Integer.MAX_VALUE);
      httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
      httpServer.createContext("/", HttpHandlers.of(200, Headers.of("Content-Type", "text/plain"), "Hello World"));
      httpServer.start();
      System.out.println("Http Server started on port 8080");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
