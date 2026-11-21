package faultpoint;

import faultpoint.RuleSet.Rule;
import io.opentelemetry.context.Context;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
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

    /** A request under its rule; written tells whether the client took the whole body, and is null without a body. */
    private record Call(String point, Rule rule, HttpRequest request, long started, AtomicBoolean written) {
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
        return new Call(point, core.decide(point), builder.build(), System.nanoTime(), written);
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

    /** The failure a fail or fail_after rule answers with: a synthetic status, or the error to throw; only a
     * fail_after has sent the request. */
    private static <T> HttpResponse<T> failure(Call call) throws IOException {
        Integer status = call.rule().integer("status");
        String sent = String.valueOf(call.rule().kind().equals("fail_after"));
        if (status != null) {
            Core.current().observe(call.point(), (status / 100) + "xx", call.elapsed(), call.rule(),
                    Map.of("status", status.toString(), "sent", sent));
            return new SyntheticResponse<>(status, call.request());
        }
        IOException error = boundaryError(call.rule());
        Core.current().observe(call.point(), outcome(error), call.elapsed(), call.rule(),
                Map.of("error", error.getClass().getName(), "sent", sent));
        throw error;
    }

    public static <T> HttpResponse<T> send(HttpClient client, HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        Core core = Core.current();
        if (!core.enabled()) {
            return client.send(request, handler);
        }
        Call call = begin(request);
        String kind = call.rule() == null ? "" : call.rule().kind();
        if (call.rule() != null) {
            Points.hold(core, call.rule());
        }
        if (kind.equals("fail")) {
            return failure(call);
        }
        HttpResponse<T> response;
        try {
            response = client.send(call.request(), handler);
            if (kind.equals("duplicate")) {
                response = client.send(call.request(), handler);
            }
        } catch (IOException failure) {
            core.observe(call.point(), outcome(failure), call.elapsed(), call.rule(), failureDetail(failure, call.sent()));
            throw failure;
        }
        if (kind.equals("fail_after")) {
            return failure(call);
        }
        core.observe(call.point(), (response.statusCode() / 100) + "xx", call.elapsed(), call.rule(),
                Map.of("status", String.valueOf(response.statusCode())));
        return response;
    }

    public static <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpClient client, HttpRequest request,
                                                                   HttpResponse.BodyHandler<T> handler) {
        Core core = Core.current();
        if (!core.enabled()) {
            return client.sendAsync(request, handler);
        }
        Call call = begin(request);
        Rule rule = call.rule();
        String kind = rule == null ? "" : rule.kind();
        if (kind.equals("crash")) {
            Points.hold(core, rule);
        }
        CompletableFuture<Void> ready = kind.equals("delay")
                ? CompletableFuture.runAsync(() -> {}, CompletableFuture.delayedExecutor((long) rule.number("ms"), TimeUnit.MILLISECONDS))
                : CompletableFuture.completedFuture(null);
        return ready.thenCompose(ignored -> {
            if (kind.equals("fail")) {
                return CompletableFuture.supplyAsync(() -> null).thenApply(nothing -> unchecked(() -> HttpClients.<T>failure(call)));
            }
            CompletableFuture<HttpResponse<T>> sent = client.sendAsync(call.request(), handler);
            if (kind.equals("duplicate")) {
                sent = sent.thenCompose(first -> client.sendAsync(call.request(), handler));
            }
            return sent.handle((response, failure) -> {
                if (failure != null) {
                    Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                    core.observe(call.point(), outcome(cause), call.elapsed(), rule, failureDetail(cause, call.sent()));
                    throw new java.util.concurrent.CompletionException(failure);
                }
                if (kind.equals("fail_after")) {
                    return unchecked(() -> HttpClients.<T>failure(call));
                }
                core.observe(call.point(), (response.statusCode() / 100) + "xx", call.elapsed(), rule,
                        Map.of("status", String.valueOf(response.statusCode())));
                return response;
            });
        });
    }

    private interface Failing<T> {
        T get() throws IOException;
    }

    private static <T> T unchecked(Failing<T> body) {
        try {
            return body.get();
        } catch (IOException failure) {
            throw new java.util.concurrent.CompletionException(failure);
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
            installation.core().declare(Map.of("rpc_client", List.of("fail", "fail_after", "duplicate", "delay", "crash")));
            Placement placement = installation.placement();
            placement.replaceCalls(OWNERS, "send", SEND, HttpClients.class, "send",
                    "(Ljava/net/http/HttpClient;" + SEND.substring(1));
            placement.replaceCalls(OWNERS, "sendAsync", SEND_ASYNC, HttpClients.class, "sendAsync",
                    "(Ljava/net/http/HttpClient;" + SEND_ASYNC.substring(1));
        }
    }
}
