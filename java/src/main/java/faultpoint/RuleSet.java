package faultpoint;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** One experiment's rules; only the generic structure is checked here, since spec/kinds.json and
 * `faultpoint check` validate kinds and actions before a rule set is installed. */
public record RuleSet(String experiment, List<Rule> rules) {

    static final Pattern POINT_SHAPE = Pattern.compile("^([^:]+):([^:]+):.+$");

    public record Trigger(Long skip, Long limit, Double probability) {
        public Trigger {
            skip = skip == null ? 0 : skip;
            probability = probability == null ? 1.0 : probability;
            if (skip < 0 || (limit != null && limit < 1) || !(probability > 0 && probability <= 1)) {
                throw new IllegalArgumentException("a trigger skips at least 0, is limited to at least 1 and has a probability in (0, 1]");
            }
        }
    }

    /** An action is a kind and free parameters, which the plugin that executes it interprets. */
    public record Rule(String id, String point, Map<String, Object> action, Map<String, String> scope, Trigger trigger) {
        public Rule {
            if (id == null || id.isEmpty() || point == null || !POINT_SHAPE.matcher(point).matches()) {
                throw new IllegalArgumentException("a rule needs an id and a point id of the shape <service>:<kind>:<locator>");
            }
            if (action == null || !(action.get("kind") instanceof String)) {
                throw new IllegalArgumentException("rule " + id + ": an action needs a kind");
            }
            scope = scope == null ? Map.of() : Map.copyOf(scope);
            trigger = trigger == null ? new Trigger(null, null, null) : trigger;
        }

        public String kind() {
            return (String) action.get("kind");
        }

        public String service() {
            return point.substring(0, point.indexOf(':'));
        }

        public String pointKind() {
            String rest = point.substring(point.indexOf(':') + 1);
            return rest.substring(0, rest.indexOf(':'));
        }

        public double number(String name) {
            if (!(action.get(name) instanceof Number number)) {
                throw new IllegalArgumentException("rule " + id + ": a " + kind() + " action needs a numeric " + name);
            }
            return number.doubleValue();
        }

        public Integer integer(String name) {
            return action.get(name) instanceof Number number ? number.intValue() : null;
        }

        public String text(String name) {
            return action.get(name) instanceof String text ? text : null;
        }
    }

    public RuleSet {
        if (experiment == null || experiment.isEmpty()) {
            throw new IllegalArgumentException("a rule set needs an experiment");
        }
        rules = rules == null ? List.of() : List.copyOf(rules);
        var identities = new HashSet<String>();
        for (Rule rule : rules) {
            if (!identities.add(rule.id())) {
                throw new IllegalArgumentException("rule id " + rule.id() + " repeats");
            }
        }
    }

    public static RuleSet parse(String text) throws IOException {
        return Settings.JSON.readValue(text, RuleSet.class);
    }

    public static String pointId(String service, String kind, String locator) {
        if (service.contains(":")) {
            throw new IllegalArgumentException("a service name cannot contain ':': " + service);
        }
        return service + ":" + kind + ":" + locator;
    }
}
