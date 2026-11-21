package faultpoint;

import java.lang.instrument.Instrumentation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;

/** Installs advice on library classes. The advice class is resolved in the class loader of each class it
 * is inlined into, together with the agent's, so it may refer to library types only that loader sees. */
final class Advices {

    private Advices() {}

    /** The methods one advice class is inlined into. */
    record Method(ElementMatcher<? super MethodDescription> methods, String adviceClass) {}

    static void install(Instrumentation instrumentation, ElementMatcher<? super TypeDescription> types, Method... advice) {
        var transformer = new AgentBuilder.Transformer.ForAdvice().include(Advices.class.getClassLoader());
        for (Method each : advice) {
            transformer = transformer.advice(each.methods(), each.adviceClass());
        }
        new AgentBuilder.Default().type(types).transform(transformer).installOn(instrumentation);
    }
}
