package faultpoint;

import io.lettuce.core.RedisCommandExecutionException;
import io.lettuce.core.protocol.RedisCommand;
import java.nio.charset.StandardCharsets;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** Inlined into RedisChannelHandler#dispatch(RedisCommand); never loaded by the agent. */
final class LettuceAdvice {

    private LettuceAdvice() {}

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    static Object enter(@Advice.Argument(0) RedisCommand<?, ?, ?> command, @Advice.Local("call") Object call) {
        call = Lettuce.enter(new String(command.getType().getBytes(), StandardCharsets.US_ASCII),
                command.getArgs() == null ? null : command.getArgs().getFirstEncodedKey(), RedisCommandExecutionException.class);
        String answer = Lettuce.answer(call);
        if ("fail".equals(answer)) {
            command.completeExceptionally(new RedisCommandExecutionException("faultpoint: injected Redis failure"));
            return command;
        }
        if (answer != null) {
            command.complete();
            return command;
        }
        return null;
    }

    @Advice.OnMethodExit
    static void exit(@Advice.Argument(0) RedisCommand<?, ?, ?> command, @Advice.Local("call") Object call,
                     @Advice.Enter Object answered,
                     @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object returned) {
        if (answered != null) {
            returned = answered;
        }
        Lettuce.observe(call, command);
    }
}
