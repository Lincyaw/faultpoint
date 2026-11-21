package faultpoint;

import faultpoint.RuleSet.Rule;
import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.bytebuddy.matcher.ElementMatchers;

/** The rpc_server point of every request a jakarta HttpServlet serves; it restores the caller's trace
 * context and baggage for the servlet. It takes no servlet types, since the servlet API may live in a
 * class loader the agent cannot see; ServletAdvice, inlined into HttpServlet, does the servlet calls. */
public final class ServletBoundary {

    static final TextMapPropagator PROPAGATOR = TextMapPropagator.composite(
            W3CTraceContextPropagator.getInstance(), W3CBaggagePropagator.getInstance());
    static final int DEFAULT_FAILURE_STATUS = 503;
    static final String DEFAULT_IDENTIFIER_SEGMENT =
            "^(\\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$";
    static volatile Pattern identifierSegment = Pattern.compile(DEFAULT_IDENTIFIER_SEGMENT);
    /** Forwards and includes enter service again; only the outermost entry is the request. */
    static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);
    /** Tomcat's exception for a response write that failed because the client had gone. */
    static final String CLIENT_ABORT = "org.apache.catalina.connector.ClientAbortException";
    /** The request attribute in which Spring's DispatcherServlet keeps an exception it resolved without a view,
     * such as a write that failed because the client had gone. */
    public static final String RESOLVED_EXCEPTION = "org.springframework.web.servlet.DispatcherServlet.EXCEPTION";

    private static final TextMapGetter<Map<String, String>> HEADERS = new TextMapGetter<>() {
        @Override
        public Iterable<String> keys(Map<String, String> headers) {
            return headers.keySet();
        }

        @Override
        public String get(Map<String, String> headers, String key) {
            return headers == null ? null : headers.get(key);
        }
    };

    private ServletBoundary() {}

    /** A request path with identifier segments replaced, so that one route is one point. */
    static String pathTemplate(String path) {
        String[] segments = path.split("/", -1);
        for (int index = 0; index < segments.length; index++) {
            if (identifierSegment.matcher(segments[index]).matches()) {
                segments[index] = "{}";
            }
        }
        return String.join("/", segments);
    }

    /** What the entry advice hands to the exit advice; the forced status is 0 without a failure rule. */
    public record Entry(String point, Rule rule, Context context, Scope scope, long started, int forcedStatus) {
        public boolean skips() {
            return rule != null && rule.kind().equals("fail");
        }
    }

    /** Begin a request, or return null when it is nested, a dispatch the container makes itself, such as an async
     * or error dispatch, or faultpoint is off. */
    public static Entry enter(String method, String uri, Map<String, String> headers, boolean clientRequest) {
        Core core = Core.current();
        int depth = DEPTH.get();
        DEPTH.set(depth + 1);
        if (depth > 0 || !clientRequest || !core.enabled()) {
            return null;
        }
        Context context = PROPAGATOR.extract(Context.root(), headers, HEADERS);
        Scope scope = context.makeCurrent();
        String point = RuleSet.pointId(core.settings.service(), "rpc_server", method + " " + pathTemplate(uri));
        Rule rule = core.decide(point);
        int forced = 0;
        if (rule != null) {
            Points.hold(core, rule);
            if (rule.kind().equals("fail") || rule.kind().equals("fail_after")) {
                Integer status = rule.integer("status");
                forced = status == null ? DEFAULT_FAILURE_STATUS : status;
            }
        }
        return new Entry(point, rule, context, scope, System.nanoTime(), forced);
    }

    /** Leave a request's service call; the request is observed now, unless it went asynchronous, when its
     * listener observes it on completion. Resolved is the exception a framework handled without failing the call. */
    public static void exit(Entry entry, int status, Throwable thrown, Object resolved, boolean asynchronous) {
        DEPTH.set(DEPTH.get() - 1);
        if (entry == null) {
            return;
        }
        try {
            if (!asynchronous) {
                observe(entry, status, thrown, clientAborted(thrown) || clientAborted(resolved));
            }
        } finally {
            entry.scope().close();
        }
    }

    /** Observe a request's status, or its error when it threw without a forced status. The servlet API tells that
     * a response was abandoned only when the container failed to write it because the client had gone, or the
     * async context timed out; a response the container writes after the servlet returns tells nothing, so the
     * detail says abandoned only when it is true. */
    static void observe(Entry entry, int status, Throwable thrown, boolean abandoned) {
        boolean failed = thrown != null && entry.forcedStatus() == 0;
        var detail = new HashMap<String, String>();
        detail.put(failed ? "error" : "status", failed ? thrown.getClass().getName() : String.valueOf(status));
        if (abandoned) {
            detail.put("abandoned", "true");
        }
        Core.current().observe(entry.point(), failed ? "error" : (status / 100) + "xx",
                (System.nanoTime() - entry.started()) / 1e6, entry.rule(), detail);
    }

    /** Whether a failure is, or is caused by, the container's report that the client went away during a write. */
    static boolean clientAborted(Object failure) {
        for (Throwable cause = failure instanceof Throwable thrown ? thrown : null; cause != null; cause = cause.getCause()) {
            if (cause.getClass().getName().equals(CLIENT_ABORT)) {
                return true;
            }
        }
        return false;
    }

    /** A jakarta AsyncListener, made through the servlet's class loader, that observes an asynchronous request when
     * it completes, in the request's context. */
    public static Object listener(Entry entry, Class<?> listenerType, Object request, Object response) throws ReflectiveOperationException {
        ClassLoader servlet = listenerType.getClassLoader();
        Method getAttribute = Class.forName("jakarta.servlet.ServletRequest", false, servlet).getMethod("getAttribute", String.class);
        Method getStatus = Class.forName("jakarta.servlet.http.HttpServletResponse", false, servlet).getMethod("getStatus");
        boolean[] timedOut = {false};
        Throwable[] failure = {null};
        return Proxy.newProxyInstance(servlet, new Class<?>[] {listenerType}, (proxy, method, arguments) -> {
            switch (method.getName()) {
                case "onTimeout" -> timedOut[0] = true;
                case "onError" -> failure[0] = (Throwable) arguments[0].getClass().getMethod("getThrowable").invoke(arguments[0]);
                case "onStartAsync" -> {
                    Method getAsyncContext = arguments[0].getClass().getMethod("getAsyncContext");
                    getAsyncContext.getReturnType().getMethod("addListener", listenerType)
                            .invoke(getAsyncContext.invoke(arguments[0]), proxy);
                }
                case "onComplete" -> {
                    try (Scope ignored = entry.context().makeCurrent()) {
                        observe(entry, (Integer) getStatus.invoke(response), failure[0], timedOut[0]
                                || clientAborted(failure[0]) || clientAborted(getAttribute.invoke(request, RESOLVED_EXCEPTION)));
                    }
                }
                case "hashCode" -> {
                    return System.identityHashCode(proxy);
                }
                case "equals" -> {
                    return proxy == arguments[0];
                }
                case "toString" -> {
                    return "faultpoint async listener";
                }
                default -> throw new UnsupportedOperationException("faultpoint async listener: " + method.getName());
            }
            return null;
        });
    }

    public static final class ServletPlugin implements Plugin {
        @Override
        public String name() {
            return "servlet";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            if (options.get("identifier_segment") instanceof String pattern) {
                identifierSegment = Pattern.compile(pattern);
            }
            installation.core().declare(Map.of("rpc_server", List.of("fail", "fail_after", "delay", "crash")));
            Advices.install(installation.instrumentation(), ElementMatchers.named("jakarta.servlet.http.HttpServlet"),
                    ElementMatchers.named("service").and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(0, ElementMatchers.named("jakarta.servlet.ServletRequest"))),
                    "faultpoint.ServletAdvice");
        }
    }
}
