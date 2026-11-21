package faultpoint;

import java.lang.instrument.Instrumentation;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.scaffold.MethodGraph;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;

/** Installs advice on library classes. The advice class is resolved in the class loader of each class it
 * is inlined into, together with the agent's, so it may refer to library types only that loader sees. */
final class Advices {

    private Advices() {}

    /** The methods one advice class is inlined into. */
    record Method(ElementMatcher<? super MethodDescription> methods, String adviceClass) {}

    /** The types a plugin advises, with the methods each of its advice classes is inlined into. */
    record Advice(ElementMatcher<? super TypeDescription> types, List<Method> methods) {}

    /** The types each class loader's classes were matched with, kept while the loader is and given up under memory
     * pressure, so that the super types every class of a loader shares are read once. */
    static final class TypeCaches extends AgentBuilder.PoolStrategy.WithTypePoolCache {
        private final Map<ClassLoader, TypePool.CacheProvider> caches = Collections.synchronizedMap(new WeakHashMap<>());

        TypeCaches() {
            super(TypePool.Default.ReaderMode.FAST);
        }

        @Override
        protected TypePool.CacheProvider locate(ClassLoader classLoader) {
            return caches.computeIfAbsent(classLoader, loader -> new TypePool.CacheProvider.Simple.UsingSoftReference());
        }
    }

    /** Install every plugin's advice as one transformer, so that each class a loader defines is matched against every
     * plugin's types once; advice changes only the methods a class declares, so a class is transformed without the
     * methods it inherits. The JDK's classes and the agent's own are never advised. */
    static void install(Instrumentation instrumentation, List<Advice> advice) {
        AgentBuilder builder = new AgentBuilder.Default(new ByteBuddy().with(MethodGraph.Compiler.ForDeclaredMethods.INSTANCE))
                .with(new TypeCaches())
                .ignore(ElementMatchers.any(), ElementMatchers.isBootstrapClassLoader().or(ElementMatchers.isExtensionClassLoader()))
                .or(ElementMatchers.nameStartsWith("faultpoint.").or(ElementMatchers.nameStartsWith("jdk.internal.reflect."))
                        .or(ElementMatchers.isSynthetic()));
        for (Advice each : advice) {
            var transformer = new AgentBuilder.Transformer.ForAdvice().include(Advices.class.getClassLoader());
            for (Method method : each.methods()) {
                transformer = transformer.advice(method.methods(), method.adviceClass());
            }
            builder = builder.type(each.types()).transform(transformer);
        }
        builder.installOn(instrumentation);
    }
}
