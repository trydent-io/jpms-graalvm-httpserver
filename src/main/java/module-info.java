module httpserver {
  requires jdk.httpserver;

  requires org.bouncycastle.provider;
  requires org.bouncycastle.pkix;
  requires org.bouncycastle.util;
  requires org.shredzone.acme4j;

  opens io.trydent.httpserver.web;
  opens io.trydent.httpserver.cert;
  opens io.trydent.httpserver;
}
