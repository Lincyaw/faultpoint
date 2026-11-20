package faultpoint;

import java.lang.instrument.Instrumentation;
import java.util.Map;

/** A plugin discovered with ServiceLoader and enabled by name from the configuration. */
public interface Plugin {

    String name();

    /** What a plugin can change while it is installed: the core, the class rewriting of the
     * configured packages, and the instrumentation for advice on library classes. */
    interface Installation {
        Core core();

        Placement placement();

        Instrumentation instrumentation();
    }

    void install(Installation installation, Map<String, Object> options);
}
