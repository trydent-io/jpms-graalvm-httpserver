package io.trydent.httpserver.gateway;

import java.util.Map;
import java.util.concurrent.*;
import java.util.function.Function;

enum Threads {
  Pool;
  final ExecutorService Service = Executors.newVirtualThreadPerTaskExecutor();
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

  <ACTION extends Action> Result send(ACTION action);

  final class Actions implements Gateway {
    private final Map<Class<? extends Action>, Function<? super Action, ? extends Result>> handlers = new ConcurrentHashMap<>();

    @SuppressWarnings("unchecked")
    @Override
    public <ACTION extends Action> Gateway register(Class<? extends ACTION> channel, Function<? super ACTION, ? extends Result> function) {
      handlers.put(channel, sup -> function.apply((ACTION) sup));
      return this;
    }

    @Override
    public <ACTION extends Action> Result send(ACTION action) {
      try {
        return CompletableFuture
          .supplyAsync(() -> handlers.get(action.getClass()), Threads.Pool.Service)
          .thenApplyAsync(it -> it.apply(action))
          .get();
      } catch (InterruptedException | ExecutionException throwable) {
        return new Result.KO(throwable);
      }
    }
  }
}
