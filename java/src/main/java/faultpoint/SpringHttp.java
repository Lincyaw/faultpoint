package faultpoint;

import faultpoint.RuleSet.Rule;
import io.opentelemetry.context.Context;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import net.bytebuddy.matcher.ElementMatchers;

/** The rpc_client point of every request Spring's ClientHttpRequest executes, which is how RestClient and
 * RestTemplate send whatever request factory they use; the request carries the current trace context and
 * baggage. SpringHttpAdvice does the Spring calls, since only the application's class loader sees Spring. */
public final class SpringHttp {

    static final int DEFAULT_FAILURE_STATUS = 503;
    /** An intercepting request executes its delegate; only the outermost execution is a point. */
    private static final ThreadLocal<int[]> DEPTH = ThreadLocal.withInitial(() -> new int[1]);

    private SpringHttp() {}

    public record Call(String point, Rule rule, long started) {
        String action() {
            return rule == null ? "" : rule.kind();
        }

        double elapsed() {
            return (System.nanoTime() - started) / 1e6;
        }
    }

    /** Begin a request and fill the headers it must carry; a fail rule with an error throws here. */
    public static Object enter(String method, URI uri, Map<String, String> headers) throws IOException {
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
        Rule rule = core.decide(point);
        Call call = new Call(point, rule, System.nanoTime());
        if (rule == null) {
            return call;
        }
        Points.hold(core, rule);
        if (call.action().equals("duplicate")) {
            core.abort("rule " + rule.id() + ": duplicate at " + point + " cannot resend a Spring request, whose body is written once");
        }
        if (call.action().equals("fail") && rule.integer("status") == null) {
            IOException error = boundaryError(rule);
            core.observe(point, outcome(error), 0, rule);
            depth[0] -= 1;
            throw error;
        }
        return call;
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
                        default -> throw new UnsupportedOperationException("faultpoint synthetic response: " + method.getName());
                    });
        } catch (ReflectiveOperationException unavailable) {
            throw new IllegalStateException("faultpoint: cannot build a Spring response", unavailable);
        }
    }

    /** The response a fail rule with a status answers with before the request is sent, or null. */
    public static Object answered(Object call, Class<?> responseType) {
        if (!(call instanceof Call running) || !running.action().equals("fail")) {
            return null;
        }
        int status = running.rule().integer("status");
        Core.current().observe(running.point(), (status / 100) + "xx", 0, running.rule());
        return synthetic(responseType, status);
    }

    /** End a request. The result is what replaces the real response under fail_after: a synthetic response,
     * or the Throwable to throw; null keeps the real outcome. */
    public static Object exit(Object call, Class<?> responseType, Object answered, int status, Throwable thrown) {
        DEPTH.get()[0] -= 1;
        if (!(call instanceof Call running) || answered != null) {
            return null;
        }
        Core core = Core.current();
        if (thrown != null) {
            core.observe(running.point(), outcome(thrown), running.elapsed(), running.rule());
            return null;
        }
        if (!running.action().equals("fail_after")) {
            core.observe(running.point(), (status / 100) + "xx", running.elapsed(), running.rule());
            return null;
        }
        Integer forced = running.rule().integer("status");
        if (forced != null) {
            core.observe(running.point(), (forced / 100) + "xx", running.elapsed(), running.rule());
            return synthetic(responseType, forced);
        }
        IOException error = boundaryError(running.rule());
        core.observe(running.point(), outcome(error), running.elapsed(), running.rule());
        return error;
    }

    public static final class SpringHttpPlugin implements Plugin {
        @Override
        public String name() {
            return "spring-http";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            installation.core().declare(Map.of("rpc_client", List.of("fail", "fail_after", "delay", "crash")));
            Advices.install(installation.instrumentation(),
                    ElementMatchers.hasSuperType(ElementMatchers.named("org.springframework.http.client.ClientHttpRequest"))
                            .and(ElementMatchers.not(ElementMatchers.isInterface())),
                    ElementMatchers.named("execute").and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract())),
                    "faultpoint.SpringHttpAdvice");
        }
    }
}
