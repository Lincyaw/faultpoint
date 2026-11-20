package faultpoint;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** The settings of the FAULTPOINT_ environment variables and of the file FAULTPOINT_CONFIG names. */
public record Settings(String service, Path rules, Path report, List<String> packages, String scopeKey, long seed,
                       Config config) {

    static final ObjectMapper JSON = new ObjectMapper().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    /** Which placement rules are applied, and the clock reads recognised as Owner.method. */
    public record Placement(Boolean branch, Boolean check, Boolean loop, List<String> clock) {
        public Placement {
            branch = branch == null || branch;
            check = check == null || check;
            loop = loop == null || loop;
            clock = clock == null ? List.of("System.currentTimeMillis", "Instant.now") : List.copyOf(clock);
        }
    }

    /** The plugins to enable (every discovered plugin when absent), their options and the placement. */
    public record Config(List<String> plugins, Map<String, Map<String, Object>> options, Placement placement) {
        public Config {
            options = options == null ? Map.of() : Map.copyOf(options);
            placement = placement == null ? new Placement(null, null, null, null) : placement;
        }

        public Map<String, Object> options(String plugin) {
            return options.getOrDefault(plugin, Map.of());
        }

        public boolean enables(String plugin) {
            return plugins == null || plugins.contains(plugin);
        }

        static Config read(String path) throws IOException {
            return path == null ? new Config(null, null, null) : JSON.readValue(Files.readString(Path.of(path)), Config.class);
        }
    }

    private static String variable(String name) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? null : value;
    }

    public static Settings fromEnvironment() throws IOException {
        String rules = variable("FAULTPOINT_RULES");
        String report = variable("FAULTPOINT_REPORT");
        String packages = variable("FAULTPOINT_PACKAGES");
        String scopeKey = variable("FAULTPOINT_SCOPE_KEY");
        String seed = variable("FAULTPOINT_SEED");
        return new Settings(
                variable("FAULTPOINT_SERVICE") == null ? "" : variable("FAULTPOINT_SERVICE"),
                rules == null ? null : Path.of(rules),
                report == null ? null : Path.of(report),
                packages == null ? List.of() : List.of(packages.split(",")),
                scopeKey == null ? "fp.scope" : scopeKey,
                seed == null ? 0 : Long.parseLong(seed),
                Config.read(variable("FAULTPOINT_CONFIG")));
    }

    public boolean enabled() {
        return rules != null || report != null;
    }
}
