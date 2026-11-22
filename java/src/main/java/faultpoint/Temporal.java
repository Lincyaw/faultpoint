package faultpoint;

import faultpoint.RuleSet.Rule;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.bytebuddy.matcher.ElementMatchers;

/** Temporal's documented client, context and activity interceptors, attached through the application's loader. */
public final class Temporal {

    static final String LOCATOR_PREFIX = "temporal:";
    static final String CONTEXT_HEADER = "faultpoint";
    static final String TRACE_CONTEXT = "trace_id";
    static final String CLIENT_FACTORY = "io.temporal.client.WorkflowClientInternalImpl";
    static final String CLIENT_OPTIONS = "io.temporal.client.WorkflowClientOptions";
    static final String WORKER_OPTIONS = "io.temporal.worker.WorkerFactoryOptions";
    static final String CLIENT_INTERCEPTOR = "io.temporal.common.interceptors.WorkflowClientInterceptor";
    static final String CLIENT_CALLS = "io.temporal.common.interceptors.WorkflowClientCallsInterceptor";
    static final String WORKER_INTERCEPTOR = "io.temporal.common.interceptors.WorkerInterceptor";
    static final String ACTIVITY_CALLS = "io.temporal.common.interceptors.ActivityInboundCallsInterceptor";
    static final String CONTEXT_PROPAGATOR = "io.temporal.common.context.ContextPropagator";
    // Construct application type names at runtime so the agent's shade relocation cannot change them.
    static final String APPLICATION_OTEL = String.join(".", "io", "opentelemetry", "api");
    static final String APPLICATION_BAGGAGE = APPLICATION_OTEL + ".baggage.Baggage";
    static final String APPLICATION_SPAN = APPLICATION_OTEL + ".trace.Span";
    static final String APPLICATION_SPAN_CONTEXT = APPLICATION_OTEL + ".trace.SpanContext";
    static final Set<String> PUBLISHING = Set.of("start", "signal", "signalWithStart", "updateWithStart", "startUpdate", "cancel", "terminate");
    static final ThreadLocal<Map<String, String>> PROPAGATED = ThreadLocal.withInitial(Map::of);
    static final ThreadLocal<ClassLoader> APPLICATION = new ThreadLocal<>();

    private Temporal() {}

    enum GrpcFailureCode {
        CANCELLED, UNKNOWN, INVALID_ARGUMENT, DEADLINE_EXCEEDED, NOT_FOUND, ALREADY_EXISTS,
        PERMISSION_DENIED, RESOURCE_EXHAUSTED, FAILED_PRECONDITION, ABORTED, OUT_OF_RANGE,
        UNIMPLEMENTED, INTERNAL, UNAVAILABLE, DATA_LOSS, UNAUTHENTICATED
    }

    static final class ApplicationScope implements AutoCloseable {
        final ClassLoader previous;

        ApplicationScope(ClassLoader loader) {
            previous = APPLICATION.get();
            APPLICATION.set(loader);
        }

        @Override
        public void close() {
            if (previous == null) APPLICATION.remove();
            else APPLICATION.set(previous);
        }
    }

    public static Object invoke(Method method, Object receiver, Object... arguments) throws Throwable {
        try {
            return method.invoke(receiver, arguments);
        } catch (InvocationTargetException failure) {
            throw failure.getCause();
        } catch (IllegalAccessException inaccessible) {
            throw Core.internalError(inaccessible);
        }
    }

    public static Object proxy(ClassLoader loader, String name, InvocationHandler handler) throws ClassNotFoundException {
        return Proxy.newProxyInstance(loader, new Class<?>[] {Class.forName(name, false, loader)}, handler);
    }

    public static Object configured(Class<?> factory, Object options) throws ReflectiveOperationException {
        boolean client = factory.getName().equals(CLIENT_FACTORY);
        ClassLoader loader = factory.getClassLoader();
        Class<?> optionType = Class.forName(client ? CLIENT_OPTIONS : WORKER_OPTIONS, false, loader);
        Object original = options == null ? optionType.getMethod("getDefaultInstance").invoke(null) : options;
        Class<?> interceptorType = Class.forName(client ? CLIENT_INTERCEPTOR : WORKER_INTERCEPTOR, false, loader);
        Object existing = optionType.getMethod(client ? "getInterceptors" : "getWorkerInterceptors").invoke(original);
        int count = existing == null ? 0 : Array.getLength(existing);
        Object interceptors = Array.newInstance(interceptorType, count + 1);
        // Worker interceptors wrap earlier entries; the innermost activity sees the application's restored trace context.
        if (count != 0) {
            System.arraycopy(existing, 0, interceptors, client ? 0 : 1, count);
        }
        Array.set(interceptors, client ? count : 0, proxy(loader, interceptorType.getName(), new Interceptor(loader)));
        Object builder = optionType.getMethod("newBuilder", optionType).invoke(null, original);
        builder.getClass().getMethod(client ? "setInterceptors" : "setWorkerInterceptors", interceptors.getClass())
                .invoke(builder, interceptors);
        if (client) {
            List<?> existingPropagators = (List<?>) optionType.getMethod("getContextPropagators").invoke(original);
            var propagators = new ArrayList<Object>(existingPropagators == null ? List.of() : existingPropagators);
            propagators.add(proxy(loader, CONTEXT_PROPAGATOR, new ContextPropagation(loader)));
            builder.getClass().getMethod("setContextPropagators", List.class).invoke(builder, propagators);
        }
        return builder.getClass().getMethod("build").invoke(builder);
    }

    static final class Interceptor implements InvocationHandler {
        final ClassLoader loader;

        Interceptor(ClassLoader loader) {
            this.loader = loader;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            return switch (method.getName()) {
                case "workflowClientCallsInterceptor" -> Temporal.proxy(loader, CLIENT_CALLS, new Calls(loader, arguments[0]));
                case "interceptActivity" -> Temporal.proxy(loader, ACTIVITY_CALLS, new ActivityCalls(loader, arguments[0]));
                case "toString" -> "faultpoint Temporal interceptor";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == arguments[0];
                default -> arguments[arguments.length - 1];
            };
        }
    }

    static final class Calls implements InvocationHandler {
        final ClassLoader loader;
        final Object next;

        Calls(ClassLoader loader, Object next) {
            this.loader = loader;
            this.next = next;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            if (!PUBLISHING.contains(method.getName())) {
                return Temporal.invoke(method, next, arguments);
            }
            Object input = arguments[0];
            String operation = method.getName();
            String destination = operation;
            if (operation.equals("signalWithStart") || operation.equals("updateWithStart")) {
                input = input.getClass().getMethod("getWorkflowStartInput").invoke(input);
            }
            if (operation.equals("start") || operation.endsWith("WithStart")) {
                destination += "/" + input.getClass().getMethod("getWorkflowType").invoke(input);
            } else if (operation.equals("signal")) {
                destination += "/" + input.getClass().getMethod("getSignalName").invoke(input);
            }
            return execute(loader, next, method, arguments, "publish", destination);
        }
    }

    static final class ActivityCalls implements InvocationHandler {
        final ClassLoader loader;
        final Object next;
        Object context;

        ActivityCalls(ClassLoader loader, Object next) {
            this.loader = loader;
            this.next = next;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            if (method.getName().equals("init")) {
                context = arguments[0];
            }
            if (!method.getName().equals("execute")) {
                return Temporal.invoke(method, next, arguments);
            }
            Class<?> contextType = Class.forName("io.temporal.activity.ActivityExecutionContext", false, loader);
            Object info = contextType.getMethod("getInfo").invoke(context);
            Class<?> infoType = Class.forName("io.temporal.activity.ActivityInfo", false, loader);
            String destination = infoType.getMethod("getActivityTaskQueue").invoke(info) + "/"
                    + infoType.getMethod("getActivityType").invoke(info);
            return execute(loader, next, method, arguments, "consume", destination);
        }
    }

    public static Object execute(ClassLoader loader, Object next, Method method, Object[] arguments,
                                 String kind, String destination) throws Throwable {
        try (var ignored = new ApplicationScope(loader)) {
            Core core = Core.current();
            String point = RuleSet.pointId(core.settings.service(), kind, LOCATOR_PREFIX + destination);
            long started = System.nanoTime();
            Rule rule = core.decide(point, Core.ACTS_BEFORE);
            if (rule != null) {
                Points.hold(core, rule);
                if (rule.kind().equals("fail")) {
                    Throwable injected = failure(loader, rule, kind);
                    core.observe(point, "error", 0, Points.since(started), rule, failureDetail(loader, injected, kind, false));
                    throw injected;
                }
            }
            Object result;
            try {
                result = invoke(method, next, arguments);
                if (rule != null && rule.kind().equals("duplicate")) {
                    result = invoke(method, next, arguments);
                }
            } catch (Throwable failure) {
                core.observe(point, "error", 0, Points.since(started), rule, failureDetail(loader, failure, kind, true));
                throw failure;
            }
            Rule after = core.decide(point, Core.ACTS_AFTER);
            if (after != null) {
                Throwable injected = failure(loader, after, kind);
                core.observe(point, "error", 0, Points.since(started), after, failureDetail(loader, injected, kind, true));
                throw injected;
            }
            core.observe(point, kind.equals("consume") ? "rows" : "ok", kind.equals("consume") ? 1 : 0,
                    Points.since(started), rule, Map.of());
            return result;
        }
    }

    public static Map<String, String> failureDetail(ClassLoader loader, Throwable failure, String kind, boolean sent)
            throws ReflectiveOperationException {
        var detail = new HashMap<>(Map.of("error", failure.getClass().getName(), "sent", String.valueOf(sent)));
        if (kind.equals("consume")) {
            Class<?> applicationFailure = Class.forName("io.temporal.failure.ApplicationFailure", false, loader);
            if (applicationFailure.isInstance(failure)) {
                detail.put("code", (String) applicationFailure.getMethod("getType").invoke(failure));
            }
        } else {
            Class<?> statusType = Class.forName("io.grpc.Status", false, loader);
            Object status = statusType.getMethod("fromThrowable", Throwable.class).invoke(null, failure);
            detail.put("code", statusType.getMethod("getCode").invoke(status).toString());
        }
        return detail;
    }

    public static Throwable failure(ClassLoader loader, Rule rule, String kind) throws ReflectiveOperationException {
        if (kind.equals("consume")) {
            Class<?> failure = Class.forName("io.temporal.failure.ApplicationFailure", false, loader);
            return (Throwable) failure.getMethod("newFailure", String.class, String.class, Object[].class)
                    .invoke(null, "faultpoint: injected activity failure", rule.text("code") == null
                            ? "faultpoint.activity" : rule.text("code"), new Object[0]);
        }
        Class<?> status = Class.forName("io.grpc.Status", false, loader);
        Object code = status.getField(rule.text("code") == null ? GrpcFailureCode.UNAVAILABLE.name() : rule.text("code")).get(null);
        return (Throwable) status.getMethod("asRuntimeException").invoke(code);
    }

    static final class ContextPropagation implements InvocationHandler {
        final ClassLoader loader;

        ContextPropagation(ClassLoader loader) {
            this.loader = loader;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) throws ReflectiveOperationException {
            Core core = Core.current();
            return switch (method.getName()) {
                case "getName", "toString" -> CONTEXT_HEADER;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == arguments[0];
                case "getCurrentContext" -> {
                    try (var ignored = new ApplicationScope(loader)) {
                        Map<String, String> current = new HashMap<>();
                        String scope = core.contextProvider().baggage(core.settings.scopeKey());
                        String trace = core.contextProvider().traceId();
                        if (scope != null) current.put(core.settings.scopeKey(), scope);
                        if (trace != null) current.put(TRACE_CONTEXT, trace);
                        yield current;
                    }
                }
                case "setCurrentContext" -> {
                    @SuppressWarnings("unchecked") Map<String, String> current = (Map<String, String>) arguments[0];
                    PROPAGATED.set(Map.copyOf(current));
                    yield null;
                }
                case "serializeContext" -> {
                    Class<?> converterType = Class.forName("io.temporal.common.converter.DefaultDataConverter", false, loader);
                    Object converter = converterType.getField("STANDARD_INSTANCE").get(null);
                    Object payload = converterType.getMethod("toPayload", Object.class).invoke(converter, arguments[0]);
                    yield Map.of(CONTEXT_HEADER, ((java.util.Optional<?>) payload).orElseThrow());
                }
                case "deserializeContext" -> {
                    Object payload = ((Map<?, ?>) arguments[0]).get(CONTEXT_HEADER);
                    if (payload == null) yield Map.of();
                    Class<?> converterType = Class.forName("io.temporal.common.converter.DefaultDataConverter", false, loader);
                    Object converter = converterType.getField("STANDARD_INSTANCE").get(null);
                    yield converterType.getMethod("fromPayload", Class.forName("io.temporal.api.common.v1.Payload", false, loader),
                                    Class.class, java.lang.reflect.Type.class).invoke(converter, payload, Map.class, Map.class);
                }
                default -> throw new UnsupportedOperationException("Temporal context: " + method.getName());
            };
        }
    }

    public static final class TemporalPlugin implements Plugin {
        @Override
        public String name() {
            return "temporal";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            Core core = installation.core();
            Core.ContextProvider original = core.contextProvider();
            core.useContext(new Core.ContextProvider() {
                @Override
                public String baggage(String key) {
                    ClassLoader loader = APPLICATION.get();
                    if (loader != null && loader.getResource(APPLICATION_BAGGAGE.replace('.', '/') + ".class") != null) {
                        try {
                            Class<?> baggageType = Class.forName(APPLICATION_BAGGAGE, false, loader);
                            String current = (String) baggageType.getMethod("getEntryValue", String.class)
                                    .invoke(baggageType.getMethod("current").invoke(null), key);
                            if (current != null) return current;
                        } catch (ReflectiveOperationException unavailable) {
                            throw Core.internalError(unavailable);
                        }
                    }
                    String current = original.baggage(key);
                    return current == null ? PROPAGATED.get().get(key) : current;
                }

                @Override
                public String traceId() {
                    ClassLoader loader = APPLICATION.get();
                    if (loader != null && loader.getResource(APPLICATION_SPAN.replace('.', '/') + ".class") != null) {
                        try {
                            Class<?> spanType = Class.forName(APPLICATION_SPAN, false, loader);
                            Class<?> contextType = Class.forName(APPLICATION_SPAN_CONTEXT, false, loader);
                            Object context = spanType.getMethod("getSpanContext").invoke(spanType.getMethod("current").invoke(null));
                            if ((boolean) contextType.getMethod("isValid").invoke(context)) {
                                return (String) contextType.getMethod("getTraceId").invoke(context);
                            }
                        } catch (ReflectiveOperationException unavailable) {
                            throw Core.internalError(unavailable);
                        }
                    }
                    String current = original.traceId();
                    return current == null ? PROPAGATED.get().get(TRACE_CONTEXT) : current;
                }
            });
            core.declare(Map.of("publish", List.of("fail", "fail_after", "duplicate", "delay", "crash"),
                    "consume", List.of("fail", "fail_after", "duplicate", "delay", "crash")),
                    locator -> locator.startsWith(LOCATOR_PREFIX));
            core.check(rule -> rule.locator().startsWith(LOCATOR_PREFIX)
                    && (rule.action().containsKey("error") || rule.action().containsKey("status") || rule.action().containsKey("when"))
                    ? "Temporal failures use code, not error, status or when" : null);
            core.check(rule -> rule.pointKind().equals("publish") && rule.locator().startsWith(LOCATOR_PREFIX)
                    && rule.text("code") != null
                    && Arrays.stream(GrpcFailureCode.values()).noneMatch(code -> code.name().equals(rule.text("code")))
                    ? "a Temporal publish failure needs a non-OK gRPC code" : null);
            // Both public client overloads reach this factory, including the overload without options.
            installation.advise(ElementMatchers.namedOneOf(CLIENT_FACTORY, "io.temporal.worker.WorkerFactory"),
                    new Advices.Method(ElementMatchers.named("newInstance").and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.isStatic()), "faultpoint.TemporalAdvice"));
        }
    }
}
