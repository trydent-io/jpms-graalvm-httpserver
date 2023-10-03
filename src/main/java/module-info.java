module httpserver {
  requires jdk.httpserver;
  requires org.bouncycastle.provider;
  requires org.bouncycastle.pkix;
  requires org.bouncycastle.util;

  opens io.trydent.httpserver.web;
  opens io.trydent.httpserver.cert;
}
