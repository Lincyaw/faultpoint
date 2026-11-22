package faultpoint;

import faultpoint.RuleSet.Rule;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLSession;

/** The rpc_client point of java.net.http calls in the configured packages, whose call sites the
 * placement routes here; the calls carry the current trace context and baggage. */
public final class HttpClients {

    static final String SEND = "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/net/http/HttpResponse;";
    static final String SEND_ASYNC = "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/util/concurrent/CompletableFuture;";

    private HttpClients() {}

    /** The failure parameters of the HTTP client and servlet adapters, checked before rules run. */
    static String checkRule(Rule rule) {
        return (rule.kind().equals("fail") || rule.kind().equals("fail_after"))
                && (rule.pointKind().equals("rpc_client") || rule.pointKind().equals("rpc_server"))
                && !rule.locator().startsWith("gRPC ") && rule.action().containsKey("code")
                ? "HTTP failures use status, not code" : null;
    }

    /** A response answered without a peer; its body is null. */
    record SyntheticResponse<T>(int statusCode, HttpRequest request) implements HttpResponse<T> {
        @Override
        public Optional<HttpResponse<T>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return HttpHeaders.of(Map.of(), (name, value) -> true);
        }

        @Override
        public T body() {
            return null;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return request.uri();
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }
    }

    /** A request under the rule decided before it; written tells whether the client took the whole body, and is null
     * without a body. An asynchronous request completes on a thread of the client, which has not its context. */
    private record Call(String point, Rule rule, HttpRequest request, long started, AtomicBoolean written, Context context) {
        double elapsed() {
            return (System.nanoTime() - started) / 1e6;
        }

        Boolean sent() {
            return written == null ? null : written.get();
        }
    }

    /** A body publisher that records when the client, its subscriber, has taken the whole body. */
    private record WatchedBody(HttpRequest.BodyPublisher body, AtomicBoolean written) implements HttpRequest.BodyPublisher {
        @Override
        public long contentLength() {
            return body.contentLength();
        }

        @Override
        public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {
            body.subscribe(new Flow.Subscriber<ByteBuffer>() {
                @Override
                public void onSubscribe(Flow.Subscription subscription) {
                    subscriber.onSubscribe(subscription);
                }

                @Override
                public void onNext(ByteBuffer item) {
                    subscriber.onNext(item);
                }

                @Override
                public void onError(Throwable failure) {
                    subscriber.onError(failure);
                }

                @Override
                public void onComplete() {
                    subscriber.onComplete();
                    written.set(true);
                }
            });
        }
    }

    private static Call begin(HttpRequest request) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(request, (name, value) -> true);
        ServletBoundary.PROPAGATOR.inject(Context.current(), builder, HttpRequest.Builder::setHeader);
        // The client never subscribes to an empty body, so only a request with a body can tell whether it was sent.
        HttpRequest.BodyPublisher body = request.bodyPublisher().filter(publisher -> publisher.contentLength() != 0).orElse(null);
        AtomicBoolean written = body == null ? null : new AtomicBoolean();
        if (body != null) {
            builder.method(request.method(), new WatchedBody(body, written));
        }
        URI uri = request.uri();
        String peer = uri.getPort() == -1 ? uri.getHost() : uri.getHost() + ":" + uri.getPort();
        Core core = Core.current();
        String point = RuleSet.pointId(core.settings.service(), "rpc_client",
                request.method() + " " + peer + ServletBoundary.pathTemplate(uri.getPath()));
        return new Call(point, core.decide(point, Core.ACTS_BEFORE), builder.build(), System.nanoTime(), written, Context.current());
    }

    /** Whether an answer is the success of an exchange, 2xx or 3xx, which is the only one fail_after replaces. */
    static boolean succeeded(int status) {
        return status >= 200 && status < 400;
    }

    /** A failed request's error type and, when known, whether the request was sent whole: never after a failed
     * connect, and otherwise as the client's taking of the body tells, which is null for a request without one. */
    static Map<String, String> failureDetail(Throwable failure, Boolean written) {
        boolean connecting = failure instanceof ConnectException || failure instanceof HttpConnectTimeoutException;
        return connecting || written != null
                ? Map.of("error", failure.getClass().getName(), "sent", String.valueOf(!connecting && written))
                : Map.of("error", failure.getClass().getName());
    }

    private static String outcome(Throwable failure) {
        if (failure instanceof HttpTimeoutException) {
            return "timeout";
        }
        return failure instanceof ConnectException ? "refused" : "error";
    }

    private static IOException boundaryError(Rule rule) {
        return "refused".equals(rule.text("error")) ? new ConnectException("faultpoint: connection refused")
                : new HttpTimeoutException("faultpoint: request timed out");
    }

    /** How long a delay, or a fail with ms, keeps the client waiting as a slow peer would; null without either. */
    private static Duration waiting(Rule rule) {
        return rule != null && Points.waits(rule)
                ? Duration.ofMillis((long) rule.number("ms")) : null;
    }

    /** A wait the caller cut short, by its timeout, a cancel or an interrupt, which it meets as failure. A delay stands
     * for a slow peer, which has the request already and runs it, so the request is sent all the same and its answer
     * dropped; a fail with ms sends nothing. An asynchronous wait ends on a thread of its own, so the request's context
     * is made current. */
    private static void cut(HttpClient client, Call call, Throwable failure) {
        boolean sent = call.rule().kind().equals("delay");
        if (sent) {
            client.sendAsync(call.request(), HttpResponse.BodyHandlers.discarding());
        }
        try (Scope ignored = call.context().makeCurrent()) {
            Core.current().observe(call.point(), outcome(failure), call.elapsed(), call.elapsed(), call.rule(),
                    Map.of("error", failure.getClass().getName(), "sent", String.valueOf(sent)));
        }
    }

    /** The request sent after a wait, with what is left of its timeout, which counts the whole exchange. */
    private static Call afterWait(Call call, Duration wait) {
        Optional<Duration> timeout = call.request().timeout();
        return timeout.isEmpty() ? call : new Call(call.point(), call.rule(),
                HttpRequest.newBuilder(call.request(), (name, value) -> true).timeout(timeout.get().minus(wait)).build(),
                call.started(), call.written(), call.context());
    }

    /** Whether the request's timeout ends a wait before it passes, as the client gives up on a slow peer. */
    private static boolean timesOut(Call call, Duration wait) {
        return call.request().timeout().filter(timeout -> timeout.compareTo(wait) <= 0).isPresent();
    }

    /** Wait as a slow peer keeps a send waiting: the request's timeout ends it with HttpTimeoutException, as the client
     * gives up, and an interrupt ends it as it ends a send; otherwise the request goes on. */
    private static Call waitAsPeer(HttpClient client, Call call, Duration wait) throws IOException, InterruptedException {
        boolean timingOut = timesOut(call, wait);
        try {
            Thread.sleep((timingOut ? call.request().timeout().get() : wait).toMillis());
        } catch (InterruptedException interrupted) {
            own(() -> {
                cut(client, call, interrupted);
                return null;
            });
            throw interrupted;
        }
        if (timingOut) {
            HttpTimeoutException timedOut = new HttpTimeoutException("request timed out");
            own(() -> {
                cut(client, call, timedOut);
                return null;
            });
            throw timedOut;
        }
        return own(() -> afterWait(call, wait));
    }

    /** The failure a fail or fail_after rule answers with: a synthetic status, or the error to throw; only a
     * fail_after has sent the request. */
    private static <T> HttpResponse<T> failure(Call call, Rule rule) throws IOException {
        Integer status = rule.integer("status");
        String sent = String.valueOf(rule.kind().equals("fail_after"));
        if (status != null) {
            Core.current().observe(call.point(), (status / 100) + "xx", call.elapsed(), call.elapsed(), rule,
                    Map.of("status", status.toString(), "sent", sent));
            return new SyntheticResponse<>(status, call.request());
        }
        IOException error = boundaryError(rule);
        Core.current().observe(call.point(), outcome(error), call.elapsed(), call.elapsed(), rule,
                Map.of("error", error.getClass().getName(), "sent", sent));
        throw error;
    }

    /** A request that got a response: a fail_after rule decided now, which only a 2xx or 3xx answer counts against
     * its trigger, answers with its failure instead; otherwise the response is observed and returned. */
    private static <T> HttpResponse<T> answered(Call call, HttpResponse<T> response) throws IOException {
        Core core = Core.current();
        Rule replacing = succeeded(response.statusCode()) ? core.decide(call.point(), Core.ACTS_AFTER) : null;
        if (replacing != null) {
            return failure(call, replacing);
        }
        core.observe(call.point(), (response.statusCode() / 100) + "xx", call.elapsed(), call.elapsed(), call.rule(),
                Map.of("status", String.valueOf(response.statusCode())));
        return response;
    }

    /** The client's own calls, whose exceptions are the application's, between the agent's work. */
    public static <T> HttpResponse<T> send(HttpClient client, HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        Core core = Core.current();
        if (!core.enabled()) {
            return client.send(request, handler);
        }
        Call begun = own(() -> begin(request));
        String kind = begun.rule() == null ? "" : begun.rule().kind();
        Duration wait = own(() -> {
            if (kind.equals("crash")) {
                Points.hold(core, begun.rule());
            }
            return waiting(begun.rule());
        });
        Call call = wait == null ? begun : waitAsPeer(client, begun, wait);
        if (kind.equals("fail")) {
            return own(() -> failure(call, call.rule()));
        }
        HttpResponse<T> response;
        try {
            response = client.send(call.request(), handler);
            if (kind.equals("duplicate")) {
                response = client.send(call.request(), handler);
            }
        } catch (IOException failure) {
            own(() -> {
                core.observe(call.point(), outcome(failure), call.elapsed(), call.elapsed(), call.rule(), failureDetail(failure, call.sent()));
                return null;
            });
            throw failure;
        }
        HttpResponse<T> received = response;
        return own(() -> answered(call, received));
    }

    /** The client's own calls, whose failures are the application's, between the agent's work, which runs on the
     * client's threads once the request is sent. */
    public static <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpClient client, HttpRequest request,
                                                                   HttpResponse.BodyHandler<T> handler) {
        Core core = Core.current();
        if (!core.enabled()) {
            return client.sendAsync(request, handler);
        }
        Call begun = unchecked(() -> begin(request));
        Rule rule = begun.rule();
        String kind = rule == null ? "" : rule.kind();
        Duration wait = unchecked(() -> {
            if (kind.equals("crash")) {
                Points.hold(core, rule);
            }
            return waiting(rule);
        });
        boolean timingOut = wait != null && timesOut(begun, wait);
        // The future the caller holds: cancelled during a wait, the caller has given up on a slow peer; cancelled after,
        // the cancel reaches the request the client sends.
        CompletableFuture<HttpResponse<T>> answer = new CompletableFuture<>();
        AtomicBoolean proceeded = new AtomicBoolean();
        answer.whenComplete((response, failure) -> {
            if (answer.isCancelled() && proceeded.compareAndSet(false, true)) {
                unchecked(() -> {
                    cut(client, begun, new CancellationException());
                    return null;
                });
            }
        });
        CompletableFuture<Void> ready = wait == null ? CompletableFuture.completedFuture(null)
                : CompletableFuture.runAsync(() -> {}, CompletableFuture.delayedExecutor(
                        (timingOut ? begun.request().timeout().get() : wait).toMillis(), TimeUnit.MILLISECONDS));
        ready.thenCompose(ignored -> {
            if (!proceeded.compareAndSet(false, true)) {
                return CompletableFuture.<HttpResponse<T>>completedFuture(null);
            }
            if (timingOut) {
                HttpTimeoutException timedOut = new HttpTimeoutException("request timed out");
                unchecked(() -> {
                    cut(client, begun, timedOut);
                    return null;
                });
                return CompletableFuture.<HttpResponse<T>>failedFuture(timedOut);
            }
            Call call = wait == null ? begun : unchecked(() -> afterWait(begun, wait));
            if (kind.equals("fail")) {
                return CompletableFuture.supplyAsync(() -> null).thenApply(nothing -> {
                    try (Scope scope = call.context().makeCurrent()) {
                        return unchecked(() -> HttpClients.<T>failure(call, rule));
                    }
                });
            }
            CompletableFuture<HttpResponse<T>> first = client.sendAsync(call.request(), handler);
            CompletableFuture<HttpResponse<T>> sent = kind.equals("duplicate")
                    ? first.thenCompose(response -> client.sendAsync(call.request(), handler)) : first;
            answer.whenComplete((response, failure) -> {
                if (answer.isCancelled()) {
                    sent.cancel(true);
                }
            });
            return sent.handle((response, failure) -> {
                try (Scope scope = call.context().makeCurrent()) {
                    if (failure != null) {
                        unchecked(() -> {
                            Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                            core.observe(call.point(), outcome(cause), call.elapsed(), call.elapsed(), rule, failureDetail(cause, call.sent()));
                            return null;
                        });
                        throw new CompletionException(failure);
                    }
                    return unchecked(() -> answered(call, response));
                }
            });
        }).whenComplete((response, failure) -> {
            if (failure == null) {
                answer.complete(response);
            } else {
                answer.completeExceptionally(failure instanceof CompletionException && failure.getCause() != null ? failure.getCause() : failure);
            }
        });
        return answer;
    }

    /** The agent's own work for a request, whose IOException is the failure a rule injects. */
    private interface Failing<T> {
        T get() throws IOException;
    }

    /** Run the agent's own work: any error of it other than an injected failure stops the process. */
    private static <T> T own(Failing<T> work) throws IOException {
        try {
            return work.get();
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** Run the agent's own work in a future of the client, which fails with an injected failure. */
    private static <T> T unchecked(Failing<T> work) {
        try {
            return own(work);
        } catch (IOException failure) {
            throw new CompletionException(failure);
        }
    }

    public static final class HttpClientPlugin implements Plugin {
        static final Set<String> OWNERS = Set.of("java/net/http/HttpClient");

        @Override
        public String name() {
            return "http-client";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            installation.core().check(HttpClients::checkRule);
            installation.core().declare(Map.of("rpc_client", List.of("fail", "fail_after", "duplicate", "delay", "crash")),
                    Core.EVERY_LOCATOR);
            Placement placement = installation.placement();
            placement.replaceCalls(OWNERS, "send", SEND, HttpClients.class, "send",
                    "(Ljava/net/http/HttpClient;" + SEND.substring(1));
            placement.replaceCalls(OWNERS, "sendAsync", SEND_ASYNC, HttpClients.class, "sendAsync",
                    "(Ljava/net/http/HttpClient;" + SEND_ASYNC.substring(1));
        }
    }
}
