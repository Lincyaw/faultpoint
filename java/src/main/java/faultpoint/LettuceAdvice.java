package faultpoint;

import io.lettuce.core.RedisChannelHandler;
import io.lettuce.core.RedisCommandExecutionException;
import io.lettuce.core.internal.ExceptionFactory;
import io.lettuce.core.protocol.AsyncCommand;
import io.lettuce.core.protocol.Command;
import io.lettuce.core.protocol.RedisCommand;
import java.nio.charset.StandardCharsets;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** Inlined into RedisChannelHandler#dispatch(RedisCommand); never loaded by the agent. */
final class LettuceAdvice {

    private LettuceAdvice() {}

    /** A fail rule answers in place of Redis; one whose wait the synchronous API's timeout cut short fails as that API
     * does on a slow server, and nothing is sent. */
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
    static Object enter(@Advice.This RedisChannelHandler<?, ?> handler, @Advice.Argument(0) RedisCommand<?, ?, ?> command,
                        @Advice.Local("call") Object call) {
        call = Lettuce.enter(new String(command.getType().getBytes(), StandardCharsets.US_ASCII),
                command.getArgs() == null ? null : command.getArgs().getFirstEncodedKey(), RedisCommandExecutionException.class,
                handler.getTimeout());
        String answer = Lettuce.answer(call);
        if ("fail".equals(answer) && Lettuce.cut(call)) {
            Lettuce.cutShort(call);
            command.completeExceptionally(ExceptionFactory.createTimeoutException(handler.getTimeout()));
            return command;
        }
        if ("fail".equals(answer)) {
            RedisCommandExecutionException failure = ExceptionFactory.createExecutionException(Lettuce.errorReply(call));
            Lettuce.failed(call, failure);
            command.completeExceptionally(failure);
            return command;
        }
        if (answer != null) {
            command.complete();
            return command;
        }
        return null;
    }

    /** A delay the synchronous API's timeout cut short stands for a slow server, which has the command already and runs
     * it: the command goes to Redis, and the API meets its timeout in a command of its own, the reply dropped. */
    @Advice.OnMethodExit(suppress = Throwable.class)
    static void exit(@Advice.This RedisChannelHandler<?, ?> handler, @Advice.Argument(0) RedisCommand<?, ?, ?> command,
                     @Advice.Local("call") Object call, @Advice.Enter Object answered,
                     @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object returned) {
        if (answered != null) {
            returned = answered;
        } else if (Lettuce.cut(call)) {
            Lettuce.cutShort(call);
            AsyncCommand<Object, Object, Object> late = new AsyncCommand<>(new Command<Object, Object, Object>(command.getType(), null));
            late.completeExceptionally(ExceptionFactory.createTimeoutException(handler.getTimeout()));
            returned = late;
        }
        Lettuce.observe(call, command);
    }
}
