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
import java.util.regex.Pattern;
import net.bytebuddy.matcher.ElementMatchers;

/** The Redis points of every command a Lettuce connection dispatches, with kinds and keys from
 * spec/redis-commands.json. LettuceAdvice does the Lettuce calls, since only the application's class loader
 * sees Lettuce. */
public final class Lettuce {

    private static final List<String> ANSWERS = List.of("fail", "empty", "drop");
    private static volatile Pattern identifier = Pattern.compile(RedisCommands.TABLE.key_identifier());

    private Lettuce() {}

    /** A dispatched command, with the request context it was dispatched in: its reply completes on an I/O
     * thread, which has none. */
    public record Call(String point, Command command, Rule rule, long started, Context context) {
        String action() {
            return rule == null ? "" : rule.kind();
        }
    }

    /** Begin a command, or return null when it is not a point. */
    public static Object enter(String name, ByteBuffer firstKey) {
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
        return new Call(point, command, rule, System.nanoTime(), Context.current());
    }

    private static boolean answered(Call call) {
        return ANSWERS.contains(call.action());
    }

    /** How the command is answered without reaching Redis: "fail", "empty" or "drop", or null when it is sent. */
    public static String answer(Object call) {
        if (!(call instanceof Call running) || !answered(running)) {
            return null;
        }
        String outcome = switch (running.action()) {
            case "fail" -> "error";
            case "empty" -> "empty";
            default -> "ok";
        };
        Core.current().observe(running.point(), outcome, 0, running.rule());
        return running.action();
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
                Core.current().observe(running.point(), outcome, (System.nanoTime() - running.started()) / 1e6, running.rule());
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
                    "consume", List.of("fail", "empty", "delay", "crash")));
            Advices.install(installation.instrumentation(),
                    ElementMatchers.named("io.lettuce.core.RedisChannelHandler"),
                    ElementMatchers.named("dispatch").and(ElementMatchers.takesArguments(1))
                            .and(ElementMatchers.takesArgument(0, ElementMatchers.named("io.lettuce.core.protocol.RedisCommand"))),
                    "faultpoint.LettuceAdvice");
        }
    }
}
