module httpserver {
  requires jdk.httpserver;

  opens io.trydent.httpserver.web;
  opens io.trydent.httpserver.cert;
  opens io.trydent.httpserver;
}
