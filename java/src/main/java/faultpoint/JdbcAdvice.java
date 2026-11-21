package faultpoint;

import java.lang.reflect.Method;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** Inlined into the execute methods of java.sql.Statement implementations. */
final class JdbcAdvice {

    private JdbcAdvice() {}

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    static Object enter(@Advice.This Object statement, @Advice.AllArguments Object[] arguments,
                        @Advice.Local("execution") Object execution) throws java.sql.SQLException {
        execution = Jdbc.enter(statement, arguments);
        return Jdbc.dropped(execution);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    static void exit(@Advice.This Object statement, @Advice.Origin Method method, @Advice.AllArguments Object[] arguments,
                     @Advice.Local("execution") Object execution, @Advice.Enter Object dropped,
                     @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object returned,
                     @Advice.Thrown(readOnly = false) Throwable thrown) throws java.sql.SQLException {
        Jdbc.Outcome outcome = Jdbc.exit(execution, statement, method, arguments, dropped, returned, thrown);
        returned = outcome.returned();
        thrown = outcome.thrown();
    }

    /** Inlined into prepareStatement and prepareCall of java.sql.Connection implementations. */
    static final class Prepare {
        private Prepare() {}

        @Advice.OnMethodExit
        static void exit(@Advice.Argument(0) Object sql, @Advice.Return Object statement) {
            Jdbc.prepared(statement, sql);
        }
    }
}
