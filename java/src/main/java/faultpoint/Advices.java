package faultpoint;

import java.lang.instrument.Instrumentation;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice.ExceptionHandler;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.scaffold.MethodGraph;
import net.bytebuddy.implementation.bytecode.Removal;
import net.bytebuddy.implementation.bytecode.StackManipulation;
import net.bytebuddy.implementation.bytecode.member.MethodInvocation;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.JavaModule;

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

    /** Stops the process for an error of a class that cannot be advised, which would otherwise load without its points. */
    static final class Failures extends AgentBuilder.Listener.Adapter {
        @Override
        public void onError(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded, Throwable error) {
            Core.internalError(new IllegalStateException("cannot advise " + typeName, error));
        }
    }

    /** Install every plugin's advice as one transformer, so that each class a loader defines is matched against every
     * plugin's types once; advice changes only the methods a class declares, so a class is transformed without the
     * methods it inherits. The JDK's classes and the agent's own are never advised, and a class whose super types the
     * type pool cannot read matches none. An error the advice code raises, which is the agent's own, stops the process
     * through Core.internalError instead of reaching the application. */
    static void install(Instrumentation instrumentation, List<Advice> advice) {
        AgentBuilder builder = new AgentBuilder.Default(new ByteBuddy().with(MethodGraph.Compiler.ForDeclaredMethods.INSTANCE))
                .with(new TypeCaches())
                .with(new Failures())
                .ignore(ElementMatchers.any(), ElementMatchers.isBootstrapClassLoader().or(ElementMatchers.isExtensionClassLoader()))
                .or(ElementMatchers.nameStartsWith("faultpoint.").or(ElementMatchers.nameStartsWith("jdk.internal.reflect."))
                        .or(ElementMatchers.isSynthetic()));
        MethodDescription.InDefinedShape internalError = TypeDescription.ForLoadedType.of(Core.class).getDeclaredMethods()
                .filter(ElementMatchers.named("internalError")).getOnly();
        ExceptionHandler stopping = new ExceptionHandler.Simple(
                new StackManipulation.Compound(MethodInvocation.invoke(internalError), Removal.SINGLE));
        for (Advice each : advice) {
            var transformer = new AgentBuilder.Transformer.ForAdvice().include(Advices.class.getClassLoader())
                    .withExceptionHandler(stopping);
            for (Method method : each.methods()) {
                transformer = transformer.advice(method.methods(), method.adviceClass());
            }
            builder = builder.type(ElementMatchers.failSafe(each.types())).transform(transformer);
        }
        builder.installOn(instrumentation);
    }
}
