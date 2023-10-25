package io.trydent.httpserver.acme;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Optional;
import java.util.function.Supplier;

import static java.lang.System.out;

public sealed interface KeyPairs extends Supplier<Optional<KeyPair>> {
  static KeyPairs fromEC() {return new From("EC");}

  default KeyPairs providedBy(String provider) {throw new IllegalStateException(STR. "Can't set provider, key-pairs is \{ this }" );}

  default KeyPairs parameter(String parameter) {throw new IllegalStateException(STR. "Can't set parameter, key-pairs is \{ this }" );}

  default KeyPairs initialize() {throw new IllegalStateException(STR. "Can't initialize, key-pairs is \{ this }" );}

  @Override
  default Optional<KeyPair> get() {throw new IllegalStateException(STR. "Can't initialize, key-pairs is \{ this }" );}

  record Failed(Throwable throwable) implements KeyPairs {
    @Override
    public Optional<KeyPair> get() {
      throwable.printStackTrace();
      return Optional.empty();
    }
  }

  record From(String algorithm) implements KeyPairs {
    @Override
    public KeyPairs providedBy(String provider) {
      try {
        return new Generated(KeyPairGenerator.getInstance(algorithm, provider));
      } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
        return new Failed(e);
      }
    }

    @Override
    public KeyPairs parameter(String parameter) {
      try {
        return new Parameterized(KeyPairGenerator.getInstance(algorithm), new ECGenParameterSpec(parameter));
      } catch (NoSuchAlgorithmException e) {
        return new Failed(e);
      }
    }
  }

  record Generated(KeyPairGenerator generator) implements KeyPairs {
    private static final String secp384r1 = "secp384r1";
    private static final String secp256r1 = "secp256r1";
    private static final String secp128r1 = "secp128r1";

    @Override
    public KeyPairs parameter(String standard) {
      return new Parameterized(generator, new ECGenParameterSpec(standard));
    }
  }

  record Parameterized(KeyPairGenerator generator, ECGenParameterSpec parameter) implements KeyPairs {
    @Override
    public KeyPairs initialize() {
      try {
        generator.initialize(parameter, new SecureRandom());
        return new Initialized(generator);
      } catch (InvalidAlgorithmParameterException e) {
        return new Failed(e);
      }
    }
  }

  record Initialized(KeyPairGenerator generator) implements KeyPairs {
    @Override
    public Optional<KeyPair> get() {
      return Optional.of(generator.generateKeyPair());
    }
  }
}
