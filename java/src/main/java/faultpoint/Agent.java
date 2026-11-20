package faultpoint;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ServiceLoader;
import java.util.jar.JarFile;
import java.util.stream.Stream;

/** Attached with `-javaagent:faultpoint-agent.jar` (for example through JAVA_TOOL_OPTIONS), so that business
 * code and its build stay free of the SDK; `java -jar faultpoint-agent.jar scan` lists the points offline. */
public final class Agent {

    static final long RULES_POLL_MS = 500;
    static final String MANIFEST_FILE = "faultpoint-manifest.json";

    private Agent() {}

    public static void premain(String arguments, Instrumentation instrumentation) throws IOException {
        Settings settings = Settings.fromEnvironment();
        if (!settings.enabled()) {
            return;
        }
        Core core = new Core(settings);
        Placement placement = new Placement(settings.service(), settings.packages(), settings.config().placement());
        core.useContext(new Defaults.OtelContext());
        if (settings.report() != null) {
            core.useSink(new Defaults.JsonlSink(settings.report(), settings.service(), settings.config().options("jsonl")));
        }
        if (settings.rules() != null) {
            core.useRuleSource(new Defaults.FileRuleSource(settings.rules(), RULES_POLL_MS));
        }
        Plugin.Installation installation = new Plugin.Installation() {
            @Override
            public Core core() {
                return core;
            }

            @Override
            public Placement placement() {
                return placement;
            }

            @Override
            public Instrumentation instrumentation() {
                return instrumentation;
            }
        };
        for (Plugin plugin : ServiceLoader.load(Plugin.class, Agent.class.getClassLoader())) {
            if (settings.config().enables(plugin.name())) {
                plugin.install(installation, settings.config().options(plugin.name()));
            }
        }
        Core.install(core);
        instrumentation.addTransformer(placement);
        core.start();
    }

    /** The class files of a directory or jar, as (path, bytes) pairs. */
    static List<java.util.Map.Entry<String, byte[]>> classes(Path location) throws IOException {
        var found = new java.util.ArrayList<java.util.Map.Entry<String, byte[]>>();
        if (Files.isDirectory(location)) {
            try (Stream<Path> paths = Files.walk(location)) {
                for (Path path : paths.filter(path -> path.toString().endsWith(".class")).sorted().toList()) {
                    found.add(java.util.Map.entry(location.relativize(path).toString(), Files.readAllBytes(path)));
                }
            }
            return found;
        }
        try (JarFile jar = new JarFile(location.toFile())) {
            for (var entry : jar.stream().filter(entry -> entry.getName().endsWith(".class"))
                    .sorted(java.util.Comparator.comparing(java.util.jar.JarEntry::getName)).toList()) {
                try (var input = jar.getInputStream(entry)) {
                    found.add(java.util.Map.entry(entry.getName(), input.readAllBytes()));
                }
            }
        }
        return found;
    }

    /** `scan --service NAME --packages a.b,c.d --classes DIR_OR_JAR [--config FILE]`: the points the agent would place. */
    public static void main(String[] arguments) throws IOException {
        var options = new LinkedHashMap<String, String>();
        for (int index = 1; index + 1 < arguments.length; index += 2) {
            options.put(arguments[index], arguments[index + 1]);
        }
        if (arguments.length == 0 || !arguments[0].equals("scan") || !options.keySet().containsAll(
                List.of("--service", "--packages", "--classes"))) {
            System.err.println("usage: java -jar faultpoint-agent.jar scan --service NAME --packages a.b,c.d --classes DIR_OR_JAR [--config FILE]");
            System.exit(2);
        }
        Settings.Config config = Settings.Config.read(options.get("--config"));
        Placement placement = new Placement(options.get("--service"), List.of(options.get("--packages").split(",")),
                config.placement());
        placement.placePoints();
        Path location = Path.of(options.get("--classes"));
        for (var entry : classes(location)) {
            String internalName = entry.getKey().substring(0, entry.getKey().length() - ".class".length()).replace('\\', '/');
            if (placement.covers(internalName)) {
                placement.rewrite(entry.getValue(), Agent.class.getClassLoader());
            }
        }
        var manifest = new LinkedHashMap<String, Object>();
        manifest.put("service", options.get("--service"));
        manifest.put("language", "java");
        manifest.put("points", placement.points());
        Path output = (Files.isDirectory(location) ? location : location.toAbsolutePath().getParent()).resolve(MANIFEST_FILE);
        Files.writeString(output, Settings.JSON.writerWithDefaultPrettyPrinter().writeValueAsString(manifest) + "\n");
        System.out.println(placement.points().size() + " points in " + output);
    }
}
