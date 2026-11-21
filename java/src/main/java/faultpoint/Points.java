package faultpoint;

import faultpoint.RuleSet.Rule;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** The point functions placed code calls; the value comes first so that bytecode passes it on the stack. Each runs
 * only the agent's own code, and throws only the checked exception a fail rule injects; any other error of it stops
 * the process through Core.internalError instead of reaching the application. */
public final class Points {

    private Points() {}

    /** Perform delay and crash, blocking the thread as contention does. */
    static void hold(Core core, Rule rule) {
        if (rule.kind().equals("delay")) {
            try {
                Thread.sleep((long) rule.number("ms"));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        if (rule.kind().equals("crash")) {
            Integer code = rule.integer("code");
            core.crash(code == null ? 1 : code);
        }
    }

    /** Whether a guarded error path runs: its natural condition, or forced by a fail rule. */
    public static boolean branch(boolean taken, String point) {
        try {
            Core core = Core.current();
            if (!core.enabled()) {
                return taken;
            }
            Rule rule = core.decide(point);
            if (rule != null) {
                hold(core, rule);
                taken = taken || rule.kind().equals("fail");
            }
            core.observe(point, taken ? "taken" : "not_taken", 0, rule, Map.of());
            return taken;
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** The result of a detector, negated by a negate rule. */
    public static boolean check(boolean result, String point) {
        try {
            Core core = Core.current();
            if (!core.enabled()) {
                return result;
            }
            Rule rule = core.decide(point);
            if (rule != null) {
                hold(core, rule);
                result = result != rule.kind().equals("negate");
            }
            core.observe(point, result ? "true" : "false", 0, rule, Map.of());
            return result;
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** One iteration of a loop, delayed by a delay rule to model contention. */
    public static void loop(String point) {
        try {
            Core core = Core.current();
            if (!core.enabled()) {
                return;
            }
            Rule rule = core.decide(point);
            if (rule != null) {
                hold(core, rule);
            }
            core.observe(point, "iteration", 0, rule, Map.of());
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** A business value, replaced by a set rule or offset by a shift rule. */
    public static double value(double observed, String point) {
        try {
            Core core = Core.current();
            if (!core.enabled()) {
                return observed;
            }
            Rule rule = core.decide(point);
            double result = observed;
            if (rule != null) {
                hold(core, rule);
                result = switch (rule.kind()) {
                    case "set" -> rule.number("value");
                    case "shift" -> observed + rule.number("amount");
                    default -> observed;
                };
            }
            core.observe(point, "observed", result, rule, Map.of());
            return result;
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    private static Rule shift(String point) {
        Core core = Core.current();
        Rule rule = core.decide(point);
        if (rule != null) {
            hold(core, rule);
        }
        core.observe(point, "read", 0, rule, Map.of());
        return rule != null && rule.kind().equals("shift") ? rule : null;
    }

    /** A clock reading in epoch milliseconds, moved by a shift rule's seconds. */
    public static long clock(long reading, String point) {
        try {
            if (!Core.current().enabled()) {
                return reading;
            }
            Rule rule = shift(point);
            return rule == null ? reading : reading + (long) (rule.number("amount") * 1000);
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** A clock reading, moved by a shift rule's seconds. */
    public static Instant clock(Instant reading, String point) {
        try {
            if (!Core.current().enabled()) {
                return reading;
            }
            Rule rule = shift(point);
            return rule == null ? reading : reading.plusMillis((long) (rule.number("amount") * 1000));
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** Whether a resource was acquired: its natural outcome, or rejected by a fail rule. */
    public static boolean acquire(boolean acquired, String point) {
        try {
            Core core = Core.current();
            if (!core.enabled()) {
                return acquired;
            }
            Rule rule = core.decide(point);
            if (rule != null) {
                hold(core, rule);
                acquired = acquired && !rule.kind().equals("fail");
            }
            core.observe(point, acquired ? "acquired" : "rejected", 0, rule, Map.of());
            return acquired;
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** A call in progress: the rule decided before it, or null, and the checked exception its callee declares. */
    private record Pending(Rule rule, Class<?> declared) {}

    /** The calls in progress on this thread, innermost last, so that a call's outcome is attributed to the rule
     * decided before it even when the callee holds call points of its own. */
    private static final ThreadLocal<java.util.ArrayDeque<Pending>> CALLS = ThreadLocal.withInitial(java.util.ArrayDeque::new);

    /** Before a call whose callee declares a checked exception: a fail rule throws that exception here, so the
     * callee does not run. */
    public static void call(String point, Class<?> declared) throws Exception {
        Exception injected;
        try {
            Core core = Core.current();
            if (!core.enabled()) {
                return;
            }
            Rule rule = core.decide(point, Core.ACTS_BEFORE);
            if (rule != null) {
                hold(core, rule);
            }
            if (rule == null || !rule.kind().equals("fail")) {
                CALLS.get().push(new Pending(rule, declared));
                return;
            }
            injected = declaredException(declared, point);
            core.observe(point, "error", 0, rule, Map.of("error", injected.getClass().getName()));
        } catch (RuntimeException | Error | ReflectiveOperationException unexpected) {
            throw Core.internalError(unexpected);
        }
        throw injected;
    }

    private static Exception declaredException(Class<?> declared, String point) throws ReflectiveOperationException {
        String message = "faultpoint: injected at " + point;
        for (var constructor : declared.getConstructors()) {
            if (constructor.getParameterCount() == 1 && constructor.getParameterTypes()[0] == String.class) {
                return (Exception) constructor.newInstance(message);
            }
        }
        return (Exception) declared.getConstructor().newInstance();
    }

    /** After a call returned: a fail_after rule decided now, which only a call that returned counts against its
     * trigger, throws the exception the callee declares in place of its result. */
    public static void returned(String point) throws Exception {
        Exception injected;
        try {
            Core core = Core.current();
            if (!core.enabled()) {
                return;
            }
            Pending pending = CALLS.get().pop();
            Rule replacing = core.decide(point, Core.ACTS_AFTER);
            if (replacing == null) {
                core.observe(point, "ok", 0, pending.rule(), Map.of());
                return;
            }
            injected = declaredException(pending.declared(), point);
            core.observe(point, "error", 0, replacing, Map.of("error", injected.getClass().getName()));
        } catch (RuntimeException | Error | ReflectiveOperationException unexpected) {
            throw Core.internalError(unexpected);
        }
        throw injected;
    }

    /** After a call threw: its own failure is observed under the rule decided before the call and not replaced, so
     * a fail_after rule neither claims nor counts it. */
    public static void raised(Throwable error, String point) {
        try {
            Core core = Core.current();
            if (core.enabled()) {
                core.observe(point, "error", 0, CALLS.get().pop().rule(), Map.of("error", error.getClass().getName()));
            }
        } catch (RuntimeException | Error unexpected) {
            throw Core.internalError(unexpected);
        }
    }

    /** Declares the in-process kinds and lets the placement put their points into the configured packages. */
    public static final class PointsPlugin implements Plugin {
        @Override
        public String name() {
            return "points";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            installation.core().declare(Map.of(
                    "branch", List.of("fail", "delay", "crash"),
                    "call", List.of("fail", "fail_after", "delay", "crash"),
                    "check", List.of("negate", "delay", "crash"),
                    "loop", List.of("delay", "crash"),
                    "value", List.of("set", "shift", "delay", "crash"),
                    "clock", List.of("shift", "delay", "crash"),
                    "acquire", List.of("fail", "delay", "crash")), Core.EVERY_LOCATOR);
            installation.placement().placePoints();
        }
    }
}
