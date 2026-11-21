package faultpoint;

import faultpoint.RedisCommands.Command;
import faultpoint.RuleSet.Rule;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
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
     * thread, which has none. The reply error is Lettuce's exception type for an error reply of Redis; cut tells that
     * the synchronous API's timeout cut the rule's wait short. */
    public record Call(String point, Command command, Rule rule, long started, Context context, Class<?> replyError, boolean cut) {
        String action() {
            return rule == null ? "" : rule.kind();
        }

        /** A failed command's exception type, for an error reply its prefix, and under a rule whether it was sent: a
         * delayed command always is, and a failed one never. */
        Map<String, String> failureDetail(Throwable failure) {
            Map<String, String> detail = new HashMap<>(Map.of("error", failure.getClass().getName()));
            Matcher prefix = REPLY_PREFIX.matcher(String.valueOf(failure.getMessage()));
            if (replyError.isInstance(failure) && prefix.lookingAt()) {
                detail.put("code", prefix.group(1));
            }
            if (action().equals("delay") || action().equals("fail")) {
                detail.put("sent", String.valueOf(action().equals("delay")));
            }
            return detail;
        }
    }

    /** Lettuce's synchronous API, which waits for a command as long as the connection's timeout. */
    private static final String SYNCHRONOUS = "io.lettuce.core.FutureSyncInvocationHandler";

    /** Begin a command, or return null when it is not a point. The timeout is the connection's, which Lettuce's
     * synchronous API waits a command for and so counts a slow server's wait against; an asynchronous caller sets none
     * of its own, as TimeoutOptions are off unless the application turns them on. */
    public static Object enter(String name, ByteBuffer firstKey, Class<?> replyError, Duration timeout) {
        long started = System.nanoTime();
        Core core = Core.current();
        Command command = RedisCommands.TABLE.commands().get(name);
        if (!core.enabled() || command == null) {
            return null;
        }
        String key = firstKey == null ? null : StandardCharsets.UTF_8.decode(firstKey.duplicate()).toString();
        String point = RuleSet.pointId(core.settings.service(), command.kind(), RedisCommands.locator(name, key, identifier));
        Rule rule = core.decide(point);
        boolean cut = false;
        if (rule != null) {
            boolean synchronous = Points.waits(rule) && StackWalker.getInstance()
                    .walk(frames -> frames.anyMatch(frame -> frame.getClassName().equals(SYNCHRONOUS)));
            cut = Points.holdWithin(core, rule, synchronous ? timeout : null);
            if (rule.kind().equals("fail_after") || rule.kind().equals("duplicate")) {
                core.abort("rule " + rule.id() + ": " + rule.kind() + " at " + point + " cannot resend a Lettuce command");
            }
        }
        return new Call(point, command, rule, started, Context.current(), replyError, cut);
    }

    /** Whether the synchronous API's timeout cut the command's wait short. */
    public static boolean cut(Object call) {
        return call instanceof Call running && running.cut();
    }

    /** Observe a command whose wait the synchronous API's timeout cut short, as that API's timeout is observed on a slow
     * server: it cancels the command. */
    public static void cutShort(Object call) {
        Call running = (Call) call;
        Core.current().observe(running.point(), "error", 0, Points.since(running.started()), running.rule(),
                running.failureDetail(new CancellationException()));
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
            Core.current().observe(running.point(), running.action().equals("empty") ? "empty" : "ok", 0,
                    Points.since(running.started()), running.rule(), Map.of());
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
        Core.current().observe(running.point(), "error", 0, Points.since(running.started()), running.rule(), running.failureDetail(failure));
    }

    /** Why a rule at a Redis point cannot be obeyed: a code that is not an upper-case word, which is not the prefix of
     * an error reply. */
    static String refusal(Rule rule) {
        String code = rule.text("code");
        Command command = RedisCommands.TABLE.commands().get(rule.locator().split(" ", 2)[0]);
        return code == null || command == null || !command.kind().equals(rule.pointKind()) || REPLY_CODE.matcher(code).matches()
                ? null : "code " + code + " at " + rule.point() + " is not the prefix of a Redis error reply, an upper-case word";
    }

    /** Observe a sent command's reply when it completes, on a thread of Lettuce, whose future would keep an error of
     * the observing to itself. */
    public static void observe(Object call, Object command) {
        if (!(call instanceof Call running) || answered(running) || running.cut() || !(command instanceof CompletionStage<?> reply)) {
            return;
        }
        reply.whenComplete((value, error) -> {
            try (Scope ignored = running.context().makeCurrent()) {
                String outcome;
                if (error != null) {
                    outcome = "error";
                } else if (running.command().empty() == null) {
                    outcome = "ok";
                } else {
                    outcome = RedisCommands.empty(running.command(), value) ? "empty" : "rows";
                }
                double elapsed = Points.since(running.started());
                Core.current().observe(running.point(), outcome, elapsed, elapsed, running.rule(),
                        error == null ? Map.of() : running.failureDetail(error));
            } catch (RuntimeException | Error unexpected) {
                throw Core.internalError(unexpected);
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
            installation.advise(
                    ElementMatchers.named("io.lettuce.core.RedisChannelHandler"),
                    new Advices.Method(ElementMatchers.named("dispatch").and(ElementMatchers.takesArguments(1))
                            .and(ElementMatchers.takesArgument(0, ElementMatchers.named("io.lettuce.core.protocol.RedisCommand"))),
                            "faultpoint.LettuceAdvice"));
        }
    }
}
