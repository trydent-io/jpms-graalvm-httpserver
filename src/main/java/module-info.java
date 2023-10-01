module httpserver {
  requires jdk.httpserver;
  requires org.shredzone.acme4j;
  requires org.bouncycastle.pkix;
  requires org.bouncycastle.provider;
  requires org.bouncycastle.util;

  opens web;
}
