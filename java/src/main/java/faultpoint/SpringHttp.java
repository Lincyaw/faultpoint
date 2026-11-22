package faultpoint;

import faultpoint.RuleSet.Rule;
import io.opentelemetry.context.Context;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import net.bytebuddy.matcher.ElementMatchers;

/** The rpc_client point of every request Spring's ClientHttpRequest executes, which is how RestClient and
 * RestTemplate send whatever request factory they use; the request carries the current trace context and
 * baggage. SpringHttpAdvice does the Spring calls, since only the application's class loader sees Spring. */
public final class SpringHttp {

    static final int DEFAULT_FAILURE_STATUS = 503;
    /** An intercepting request executes its delegate; only the outermost execution is a point. */
    private static final ThreadLocal<int[]> DEPTH = ThreadLocal.withInitial(() -> new int[1]);
    /** The outermost request this thread executes, whose body the request implementation writes. */
    private static final ThreadLocal<Call> CURRENT = new ThreadLocal<>();

    private SpringHttp() {}

    /** A request under its rule; written tells whether its body was written whole, and holds null without a body. */
    public record Call(String point, Rule rule, long started, AtomicReference<Boolean> written) {
        String action() {
            return rule == null ? "" : rule.kind();
        }

        double elapsed() {
            return (System.nanoTime() - started) / 1e6;
        }
    }

    /** Begin a request and fill the headers it must carry. */
    public static Object enter(String method, URI uri, Map<String, String> headers) {
        int[] depth = DEPTH.get();
        depth[0] += 1;
        Core core = Core.current();
        if (depth[0] > 1 || !core.enabled()) {
            return null;
        }
        ServletBoundary.PROPAGATOR.inject(Context.current(), headers, Map::put);
        String peer = uri.getPort() == -1 ? uri.getHost() : uri.getHost() + ":" + uri.getPort();
        String point = RuleSet.pointId(core.settings.service(), "rpc_client",
                method + " " + peer + ServletBoundary.pathTemplate(uri.getPath()));
        Rule rule = core.decide(point, Core.ACTS_BEFORE);
        Call call = new Call(point, rule, System.nanoTime(), new AtomicReference<>());
        if (rule != null) {
            Points.hold(core, rule);
        }
        if (call.action().equals("duplicate")) {
            core.abort("rule " + rule.id() + ": duplicate at " + point + " cannot resend a Spring request, whose body is written once");
        }
        CURRENT.set(call);
        return call;
    }

    /** The body of the request this thread executes, made to record when its writing finished, as a proxy of the
     * application's Body type; the writing may run on a thread of the client. */
    public static Object watched(Object body, Class<?> bodyType) {
        Call call = CURRENT.get();
        if (body == null || call == null) {
            return body;
        }
        call.written().set(false);
        return Proxy.newProxyInstance(bodyType.getClassLoader(), new Class<?>[] {bodyType}, (proxy, method, arguments) -> {
            Object result;
            try {
                result = method.invoke(body, arguments);
            } catch (InvocationTargetException failure) {
                throw failure.getCause();
            } catch (IllegalAccessException inaccessible) {
                throw Core.internalError(inaccessible);
            }
            if (method.getName().equals("writeTo")) {
                call.written().set(true);
            }
            return result;
        });
    }

    private static IOException boundaryError(Rule rule) {
        return "refused".equals(rule.text("error")) ? new ConnectException("faultpoint: connection refused")
                : new SocketTimeoutException("faultpoint: read timed out");
    }

    private static String outcome(Throwable failure) {
        if (failure instanceof SocketTimeoutException || failure instanceof java.net.http.HttpTimeoutException) {
            return "timeout";
        }
        return failure instanceof ConnectException ? "refused" : "error";
    }

    /** A response answered without a peer, implementing the application's ClientHttpResponse type; its
     * status and headers are Spring values made through the same class loader. */
    static Object synthetic(Class<?> responseType, int status) {
        ClassLoader loader = responseType.getClassLoader();
        try {
            Object code = Class.forName("org.springframework.http.HttpStatusCode", false, loader)
                    .getMethod("valueOf", int.class).invoke(null, status);
            Object headers = Class.forName("org.springframework.http.HttpHeaders", false, loader)
                    .getConstructor().newInstance();
            return Proxy.newProxyInstance(loader, new Class<?>[] {responseType}, (proxy, method, arguments) ->
                    switch (method.getName()) {
                        case "getStatusCode" -> code;
                        case "getStatusText" -> "";
                        case "getHeaders" -> headers;
                        case "getBody" -> new ByteArrayInputStream(new byte[0]);
                        case "close" -> null;
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == arguments[0];
                        case "toString" -> "faultpoint synthetic response " + status;
                        default -> throw Core.internalError(new UnsupportedOperationException("faultpoint synthetic response: " + method.getName()));
                    });
        } catch (ReflectiveOperationException unavailable) {
            throw new IllegalStateException("faultpoint: cannot build a Spring response", unavailable);
        }
    }

    /** What a fail rule answers with in place of sending the request: a response of its status, or without one the
     * error the exit advice throws; null sends the request. */
    public static Object answered(Object call, Class<?> responseType) {
        if (!(call instanceof Call running) || !running.action().equals("fail")) {
            return null;
        }
        Integer status = running.rule().integer("status");
        if (status == null) {
            IOException error = boundaryError(running.rule());
            Core.current().observe(running.point(), outcome(error), 0, running.elapsed(), running.rule(),
                    Map.of("error", error.getClass().getName(), "sent", "false"));
            return error;
        }
        Core.current().observe(running.point(), (status / 100) + "xx", 0, running.elapsed(), running.rule(),
                Map.of("status", String.valueOf(status), "sent", "false"));
        return synthetic(responseType, status);
    }

    /** End a request. The result is what replaces the real response under fail_after: a synthetic response,
     * or the Throwable to throw; null keeps the real outcome. */
    public static Object exit(Object call, Class<?> responseType, Object answered, int status, Throwable thrown) {
        if (--DEPTH.get()[0] == 0) {
            CURRENT.remove();
        }
        if (!(call instanceof Call running) || answered != null) {
            return null;
        }
        Core core = Core.current();
        if (thrown != null) {
            core.observe(running.point(), outcome(thrown), running.elapsed(), running.elapsed(), running.rule(),
                    HttpClients.failureDetail(thrown, running.written().get()));
            return null;
        }
        Rule replacing = HttpClients.succeeded(status) ? core.decide(running.point(), Core.ACTS_AFTER) : null;
        if (replacing == null) {
            core.observe(running.point(), (status / 100) + "xx", running.elapsed(), running.elapsed(), running.rule(),
                    Map.of("status", String.valueOf(status)));
            return null;
        }
        Integer forced = replacing.integer("status");
        if (forced != null) {
            core.observe(running.point(), (forced / 100) + "xx", running.elapsed(), running.elapsed(), replacing,
                    Map.of("status", forced.toString(), "sent", "true"));
            return synthetic(responseType, forced);
        }
        IOException error = boundaryError(replacing);
        core.observe(running.point(), outcome(error), running.elapsed(), running.elapsed(), replacing,
                Map.of("error", error.getClass().getName(), "sent", "true"));
        return error;
    }

    public static final class SpringHttpPlugin implements Plugin {
        @Override
        public String name() {
            return "spring-http";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            installation.core().check(HttpClients::checkRule);
            installation.core().declare(Map.of("rpc_client", List.of("fail", "fail_after", "delay", "crash")), Core.EVERY_LOCATOR);
            installation.advise(
                    ElementMatchers.hasSuperType(ElementMatchers.named("org.springframework.http.client.ClientHttpRequest"))
                            .and(ElementMatchers.not(ElementMatchers.isInterface())),
                    new Advices.Method(ElementMatchers.named("execute").and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract())), "faultpoint.SpringHttpAdvice"));
            installation.advise(
                    ElementMatchers.hasSuperType(ElementMatchers.named("org.springframework.http.client.AbstractStreamingClientHttpRequest")),
                    new Advices.Method(ElementMatchers.named("executeInternal").and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(1, ElementMatchers.named("org.springframework.http.StreamingHttpOutputMessage$Body")))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract())), "faultpoint.SpringHttpAdvice$Streaming"));
        }
    }
}
