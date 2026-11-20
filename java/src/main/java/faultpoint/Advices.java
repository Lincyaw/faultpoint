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

    static void install(Instrumentation instrumentation, ElementMatcher<? super TypeDescription> types,
                        ElementMatcher<? super MethodDescription> methods, String adviceClass) {
        new AgentBuilder.Default()
                .type(types)
                .transform(new AgentBuilder.Transformer.ForAdvice()
                        .include(Advices.class.getClassLoader())
                        .advice(methods, adviceClass))
                .installOn(instrumentation);
    }
}
