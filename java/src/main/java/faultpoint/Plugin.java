package faultpoint;

import java.util.Map;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;

/** A plugin discovered with ServiceLoader and enabled by name from the configuration. */
public interface Plugin {

    String name();

    /** What a plugin can change while it is installed: the core, the class rewriting of the
     * configured packages, and the advice it inlines into library classes. */
    interface Installation {
        Core core();

        Placement placement();

        void advise(ElementMatcher<? super TypeDescription> types, Advices.Method... methods);
    }

    void install(Installation installation, Map<String, Object> options);
}
