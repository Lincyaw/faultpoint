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
        // The placement transforms before the plugins' advice, so it sees a class's original bytes, as the offline scan does.
        instrumentation.addTransformer(placement);
        for (Plugin plugin : ServiceLoader.load(Plugin.class, Agent.class.getClassLoader())) {
            if (settings.config().enables(plugin.name())) {
                plugin.install(installation, settings.config().options(plugin.name()));
            }
        }
        Core.install(core);
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

    /** The entries of a class path as the java launcher reads it, where an entry `DIR/*` stands for the jars in DIR. */
    static List<Path> classPath(String classPath) throws IOException {
        var entries = new java.util.ArrayList<Path>();
        for (String entry : classPath.split(java.io.File.pathSeparator)) {
            if (entry.equals("*") || entry.endsWith(java.io.File.separator + "*")) {
                try (Stream<Path> jars = Files.list(Path.of(entry.substring(0, entry.length() - 1)))) {
                    jars.filter(jar -> jar.toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jar")).sorted().forEach(entries::add);
                }
            } else if (!entry.isEmpty()) {
                entries.add(Path.of(entry));
            }
        }
        return entries;
    }

    /** `scan --service NAME --packages a.b,c.d --classes DIR_OR_JAR --classpath CLASS_PATH [--config FILE]`: the points
     * the agent would place in the classes of DIR_OR_JAR and of the class path in the placement scope. */
    public static void main(String[] arguments) throws IOException {
        var options = new LinkedHashMap<String, String>();
        for (int index = 1; index + 1 < arguments.length; index += 2) {
            options.put(arguments[index], arguments[index + 1]);
        }
        if (arguments.length == 0 || !arguments[0].equals("scan") || !options.keySet().containsAll(
                List.of("--service", "--packages", "--classes", "--classpath"))) {
            System.err.println("usage: java -jar faultpoint-agent.jar scan --service NAME --packages a.b,c.d --classes DIR_OR_JAR "
                    + "--classpath CLASS_PATH [--config FILE]\n  CLASS_PATH is the class path the service runs with, as java -cp "
                    + "takes it; call points exist only where the callee's class file shows a checked exception");
            System.exit(2);
        }
        Settings.Config config = Settings.Config.read(options.get("--config"));
        Placement placement = new Placement(options.get("--service"), List.of(options.get("--packages").split(",")),
                config.placement());
        placement.placePoints();
        Path location = Path.of(options.get("--classes"));
        // The class path usually holds the scanned classes too; each location is read once, or its points would repeat.
        var locations = new java.util.LinkedHashSet<Path>();
        for (Path each : java.util.stream.Stream.concat(Stream.of(location), classPath(options.get("--classpath")).stream()).toList()) {
            locations.add(each.toAbsolutePath().normalize());
        }
        var path = new java.util.ArrayList<java.net.URL>();
        for (Path each : locations) {
            path.add(each.toUri().toURL());
        }
        // Call points depend on the exceptions callees declare, and library points on the jars in the placement scope,
        // so the scan reads the same class path the service runs with.
        try (var loader = new java.net.URLClassLoader(path.toArray(java.net.URL[]::new), ClassLoader.getPlatformClassLoader())) {
            for (Path each : locations) {
                for (var entry : classes(each)) {
                    String internalName = entry.getKey().substring(0, entry.getKey().length() - ".class".length()).replace('\\', '/');
                    Placement.Target target = placement.target(internalName, each.toString());
                    if (target != null) {
                        placement.rewrite(entry.getValue(), loader, target);
                    }
                }
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
