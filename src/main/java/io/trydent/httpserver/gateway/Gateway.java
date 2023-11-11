package io.trydent.httpserver.gateway;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Function;

enum Threads {
  Pool;
  final ExecutorService service = Executors.newVirtualThreadPerTaskExecutor();
}

public sealed interface Gateway {
  sealed interface Action {
    record Send(String message) implements Action {}

    record Submit(String command) implements Action {}
  }

  sealed interface Result {
    record OK(String message) implements Result {}

    record KO(Throwable throwable) implements Result {}
  }

  static Gateway actions() {
    return new Actions();
  }

  <ACTION extends Action> Gateway register(Class<? extends ACTION> channel, Function<? super ACTION, ? extends Result> function);

  <ACTION extends Action> Future<Result> send(ACTION action);

  final class Actions implements Gateway {
    private final Map<Class<? extends Action>, Function<? super Action, ? extends Result>> handlers = new ConcurrentHashMap<>();

    @SuppressWarnings("unchecked")
    @Override
    public <ACTION extends Action> Gateway register(Class<? extends ACTION> channel, Function<? super ACTION, ? extends Result> function) {
      handlers.put(channel, sup -> function.apply((ACTION) sup));
      return this;
    }

    @Override
    public <ACTION extends Action> Future<Result> send(ACTION action) {;
      return Threads.Pool.service.submit(() -> handlers.get(action.getClass()).apply(action));
    }
  }
}
