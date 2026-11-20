package faultpoint;

import faultpoint.RuleSet.Rule;
import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
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
    public record Entry(String point, Rule rule, Scope scope, long started, int forcedStatus) {
        public boolean skips() {
            return rule != null && rule.kind().equals("fail");
        }
    }

    /** Begin a request, or return null when it is nested or faultpoint is off. */
    public static Entry enter(String method, String uri, Map<String, String> headers) {
        Core core = Core.current();
        int depth = DEPTH.get();
        DEPTH.set(depth + 1);
        if (depth > 0 || !core.enabled()) {
            return null;
        }
        Scope scope = PROPAGATOR.extract(Context.root(), headers, HEADERS).makeCurrent();
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
        return new Entry(point, rule, scope, System.nanoTime(), forced);
    }

    public static void exit(Entry entry, int status, boolean thrown) {
        DEPTH.set(DEPTH.get() - 1);
        if (entry == null) {
            return;
        }
        try {
            String outcome = thrown && entry.forcedStatus() == 0 ? "error" : (status / 100) + "xx";
            Core.current().observe(entry.point(), outcome, (System.nanoTime() - entry.started()) / 1e6, entry.rule());
        } finally {
            entry.scope().close();
        }
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
