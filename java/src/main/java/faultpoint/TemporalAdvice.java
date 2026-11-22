package faultpoint;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** Inlined into the client and worker factories that install Temporal's documented interceptors. */
final class TemporalAdvice {

    private TemporalAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    static void enter(@Advice.Origin Class<?> factory,
                      @Advice.Argument(value = 1, readOnly = false, typing = Assigner.Typing.DYNAMIC) Object options)
            throws ReflectiveOperationException {
        options = Temporal.configured(factory, options);
    }
}
