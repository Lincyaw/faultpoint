package faultpoint;

import faultpoint.RedisCommands.Command;
import faultpoint.RuleSet.Rule;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.bytebuddy.matcher.ElementMatchers;

/** The Redis points of every command a Lettuce connection dispatches, with kinds and keys from
 * spec/redis-commands.json. LettuceAdvice does the Lettuce calls, since only the application's class loader
 * sees Lettuce. */
public final class Lettuce {

    private static final List<String> ANSWERS = List.of("fail", "empty", "drop");
    /** The prefix of an error reply, which Redis writes as an upper-case word. */
    private static final Pattern REPLY_CODE = Pattern.compile("[A-Z][A-Z0-9_]*");
    private static final Pattern REPLY_PREFIX = Pattern.compile("(" + REPLY_CODE.pattern() + ")(?: |$)");
    private static volatile Pattern identifier = Pattern.compile(RedisCommands.TABLE.key_identifier());

    private Lettuce() {}

    /** A dispatched command, with the request context it was dispatched in: its reply completes on an I/O
     * thread, which has none. The reply error is Lettuce's exception type for an error reply of Redis. */
    public record Call(String point, Command command, Rule rule, long started, Context context, Class<?> replyError) {
        String action() {
            return rule == null ? "" : rule.kind();
        }

        /** A failed command's exception type and, for an error reply, its prefix. */
        Map<String, String> failureDetail(Throwable failure) {
            Matcher prefix = REPLY_PREFIX.matcher(String.valueOf(failure.getMessage()));
            return replyError.isInstance(failure) && prefix.lookingAt()
                    ? Map.of("error", failure.getClass().getName(), "code", prefix.group(1))
                    : Map.of("error", failure.getClass().getName());
        }
    }

    /** Begin a command, or return null when it is not a point. */
    public static Object enter(String name, ByteBuffer firstKey, Class<?> replyError) {
        Core core = Core.current();
        Command command = RedisCommands.TABLE.commands().get(name);
        if (!core.enabled() || command == null) {
            return null;
        }
        String key = firstKey == null ? null : StandardCharsets.UTF_8.decode(firstKey.duplicate()).toString();
        String point = RuleSet.pointId(core.settings.service(), command.kind(), RedisCommands.locator(name, key, identifier));
        Rule rule = core.decide(point);
        if (rule != null) {
            Points.hold(core, rule);
            if (rule.kind().equals("fail_after") || rule.kind().equals("duplicate")) {
                core.abort("rule " + rule.id() + ": " + rule.kind() + " at " + point + " cannot resend a Lettuce command");
            }
        }
        return new Call(point, command, rule, System.nanoTime(), Context.current(), replyError);
    }

    private static boolean answered(Call call) {
        return ANSWERS.contains(call.action());
    }

    /** How the command is answered without reaching Redis: "fail", "empty" or "drop", or null when it is sent; a
     * fail is observed when its error is made. */
    public static String answer(Object call) {
        if (!(call instanceof Call running) || !answered(running)) {
            return null;
        }
        if (!running.action().equals("fail")) {
            Core.current().observe(running.point(), running.action().equals("empty") ? "empty" : "ok", 0, running.rule(), Map.of());
        }
        return running.action();
    }

    /** The error reply a fail rule answers with; its code is the prefix, so that Lettuce makes the exception it
     * makes for a reply of that code. */
    public static String errorReply(Object call) {
        String code = ((Call) call).rule().text("code");
        return code == null ? "faultpoint: injected Redis failure" : code + " faultpoint: injected Redis failure";
    }

    /** Observe the error a fail rule answers with. */
    public static void failed(Object call, Throwable failure) {
        Call running = (Call) call;
        Core.current().observe(running.point(), "error", 0, running.rule(), running.failureDetail(failure));
    }

    /** Why a rule at a Redis point cannot be obeyed: a code that is not an upper-case word, which is not the prefix of
     * an error reply. */
    static String refusal(Rule rule) {
        String code = rule.text("code");
        Command command = RedisCommands.TABLE.commands().get(rule.locator().split(" ", 2)[0]);
        return code == null || command == null || !command.kind().equals(rule.pointKind()) || REPLY_CODE.matcher(code).matches()
                ? null : "code " + code + " at " + rule.point() + " is not the prefix of a Redis error reply, an upper-case word";
    }

    /** Observe a sent command's reply when it completes. */
    public static void observe(Object call, Object command) {
        if (!(call instanceof Call running) || answered(running) || !(command instanceof CompletionStage<?> reply)) {
            return;
        }
        reply.whenComplete((value, error) -> {
            String outcome;
            if (error != null) {
                outcome = "error";
            } else if (running.command().empty() == null) {
                outcome = "ok";
            } else {
                outcome = RedisCommands.empty(running.command(), value) ? "empty" : "rows";
            }
            try (Scope ignored = running.context().makeCurrent()) {
                Core.current().observe(running.point(), outcome, (System.nanoTime() - running.started()) / 1e6, running.rule(),
                        error == null ? Map.of() : running.failureDetail(error));
            }
        });
    }

    public static final class LettucePlugin implements Plugin {
        @Override
        public String name() {
            return "lettuce";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            identifier = RedisCommands.identifier(options);
            installation.core().declare(Map.of(
                    "store_read", List.of("fail", "empty", "delay", "crash"),
                    "store_write", List.of("fail", "drop", "delay", "crash"),
                    "publish", List.of("fail", "drop", "delay", "crash"),
                    "consume", List.of("fail", "empty", "delay", "crash")), RedisCommands::commandLocator);
            installation.core().check(Lettuce::refusal);
            Advices.install(installation.instrumentation(),
                    ElementMatchers.named("io.lettuce.core.RedisChannelHandler"),
                    ElementMatchers.named("dispatch").and(ElementMatchers.takesArguments(1))
                            .and(ElementMatchers.takesArgument(0, ElementMatchers.named("io.lettuce.core.protocol.RedisCommand"))),
                    "faultpoint.LettuceAdvice");
        }
    }
}
