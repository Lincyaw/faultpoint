package faultpoint;

import faultpoint.RuleSet.Rule;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/** Obtains rules, selects the rule of an execution and hands observations to the sink; every kind's
 * semantics lives in the plugins, which declare the kinds they serve and the actions they implement. */
public final class Core {

    static final int INVALID_RULES_EXIT = 70;

    /** One execution of a point, as the core hands it to the observation sink; the detail tells executions of one
     * outcome apart by bounded values under the keys spec/kinds.json gives the kind. */
    public record Observation(String experiment, String point, String outcome, String scope, String rule,
                              double quantity, String traceId, Map<String, String> detail) {}

    public interface RuleSource {
        /** Deliver the first rule set before returning, then every change; a failure is an unusable rule set. */
        void start(Consumer<RuleSet> apply, Consumer<String> fail);
    }

    public interface ObservationSink {
        void add(Observation observation);

        void flush();
    }

    public interface ContextProvider {
        String baggage(String key);

        String traceId();
    }

    private record RuleState(String experiment, Map<String, List<Rule>> rules) {}

    private static final class Counter {
        long matches;
        long injections;
        long drawn;
    }

    private static volatile Core current = new Core(new Settings("", null, null, List.of(), "fp.scope", 0,
            new Settings.Config(null, null, null)));

    /** The locators of every point of a kind, for a plugin that serves them all. */
    public static final Predicate<String> EVERY_LOCATOR = locator -> true;
    private static final Predicate<String> EVERY_ACTION = action -> true;
    /** fail_after acts only on an operation that completed normally, so a point decides and counts it only then;
     * every other action acts before the operation. */
    public static final Predicate<String> ACTS_AFTER = "fail_after"::equals;
    public static final Predicate<String> ACTS_BEFORE = ACTS_AFTER.negate();

    /** The kinds one plugin serves with the actions it implements there, at the points whose locators it serves. */
    private record Declaration(Map<String, List<String>> kinds, Predicate<String> locators) {}

    public final Settings settings;
    private final List<Declaration> declarations = new ArrayList<>();
    /** Each answers why its plugin cannot obey a rule, or null; a plugin passes over the kinds it does not serve. */
    private final List<Function<Rule, String>> checks = new ArrayList<>();
    private final List<RuleSource> sources = new ArrayList<>();
    private final Map<String, Counter> counters = new HashMap<>();
    private volatile RuleState state = new RuleState("", Map.of());
    private ObservationSink sink;
    private ContextProvider context;

    Core(Settings settings) {
        this.settings = settings;
        if (settings.enabled() && settings.service().isEmpty()) {
            throw new IllegalStateException("FAULTPOINT_SERVICE is required when faultpoint is enabled");
        }
    }

    /** The process's core; it observes nothing until the agent installs one. */
    public static Core current() {
        return current;
    }

    static void install(Core core) {
        current = core;
    }

    public boolean enabled() {
        return settings.enabled();
    }

    /** The kinds a plugin serves with the actions it implements there, at the points whose locators have the shape
     * its adapter makes. A point served by several plugins accepts only the actions every one of them implements,
     * so that a rule is rejected when its rule set loads rather than at the one point that cannot obey it. */
    public void declare(Map<String, List<String>> kinds, Predicate<String> locators) {
        declarations.add(new Declaration(kinds, locators));
    }

    /** A check of every rule of this service when its rule set loads, for what an action's parameters ask that a
     * plugin cannot do, so that the rule set is refused rather than one point failing to obey it. */
    public void check(Function<Rule, String> refusal) {
        checks.add(refusal);
    }

    public void useRuleSource(RuleSource source) {
        sources.add(source);
    }

    public void useSink(ObservationSink sink) {
        this.sink = sink;
    }

    public void useContext(ContextProvider context) {
        this.context = context;
    }

    void start() {
        for (RuleSource source : sources) {
            source.start(this::apply, reason -> abort("unusable rules: " + reason));
        }
    }

    /** Install a rule set; a rule of this service at a point plugins serve must use an action each of those plugins
     * implements, a rule of a kind plugins here serve at a point none of them serves is refused, and rules of other
     * services or of kinds no plugin here serves are left to their processes. */
    void apply(RuleSet ruleset) {
        var rules = new HashMap<String, List<Rule>>();
        for (Rule rule : ruleset.rules()) {
            List<Declaration> ofKind = declarations.stream().filter(declaration -> declaration.kinds().containsKey(rule.pointKind())).toList();
            if (ofKind.isEmpty() || !rule.service().equals(settings.service())) {
                continue;
            }
            List<List<String>> serving = ofKind.stream().filter(declaration -> declaration.locators().test(rule.locator()))
                    .map(declaration -> declaration.kinds().get(rule.pointKind())).toList();
            if (serving.isEmpty()) {
                abort("rule " + rule.id() + ": no plugin of this process serves " + rule.point());
            }
            if (!serving.stream().allMatch(actions -> actions.contains(rule.kind()))) {
                abort("rule " + rule.id() + ": not every plugin of this process serving its point implements " + rule.kind()
                        + " at " + rule.point());
            }
            for (Function<Rule, String> check : checks) {
                String refusal = check.apply(rule);
                if (refusal != null) {
                    abort("rule " + rule.id() + ": " + refusal);
                }
            }
            rules.computeIfAbsent(rule.point(), ignored -> new ArrayList<>()).add(rule);
        }
        flush();
        synchronized (counters) {
            counters.clear();
        }
        state = new RuleState(ruleset.experiment(), rules);
    }

    private static double draw(String seed) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(seed.getBytes(StandardCharsets.UTF_8));
            return Integer.toUnsignedLong(ByteBuffer.wrap(digest).getInt()) / 4294967296.0;
        } catch (NoSuchAlgorithmException missing) {
            throw new IllegalStateException(missing);
        }
    }

    /** The first rule of a point whose scope matches the current request and whose trigger fires. */
    public Rule decide(String point) {
        return decide(point, EVERY_ACTION);
    }

    /** The first rule of a point among the rules of the given actions whose scope matches the current request and
     * whose trigger fires. Only those rules are counted, so that a point deciding before and after its operation
     * counts a rule only where it can act. */
    public Rule decide(String point, Predicate<String> actions) {
        List<Rule> rules = state.rules().get(point);
        if (rules == null) {
            return null;
        }
        for (Rule rule : rules) {
            if (!actions.test(rule.kind())
                    || !rule.scope().entrySet().stream().allMatch(entry -> entry.getValue().equals(baggage(entry.getKey())))) {
                continue;
            }
            synchronized (counters) {
                Counter counter = counters.computeIfAbsent(rule.id(), ignored -> new Counter());
                counter.matches += 1;
                if (counter.matches <= rule.trigger().skip()
                        || (rule.trigger().limit() != null && counter.injections >= rule.trigger().limit())) {
                    continue;
                }
                double drawn = draw(settings.seed() + ":" + rule.id() + ":" + counter.drawn++);
                if (drawn >= rule.trigger().probability()) {
                    continue;
                }
                counter.injections += 1;
            }
            return rule;
        }
        return null;
    }

    public void observe(String point, String outcome, double quantity, Rule rule, Map<String, String> detail) {
        if (sink == null) {
            return;
        }
        String scope = baggage(settings.scopeKey());
        sink.add(new Observation(state.experiment(), point, outcome, scope == null ? "" : scope,
                rule == null ? null : rule.id(), quantity, context == null ? null : context.traceId(), detail));
    }

    private String baggage(String key) {
        return context == null ? null : context.baggage(key);
    }

    public void flush() {
        if (sink != null) {
            sink.flush();
        }
    }

    public void crash(int code) {
        flush();
        Runtime.getRuntime().halt(code);
    }

    /** End the process when rules cannot be obeyed, so that no experiment runs under rules it did not ask for. */
    public void abort(String reason) {
        System.err.println("faultpoint: " + reason + "; stopping the process");
        crash(INVALID_RULES_EXIT);
    }
}
