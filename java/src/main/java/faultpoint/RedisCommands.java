package faultpoint;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Map;
import java.util.regex.Pattern;

/** spec/redis-commands.json: which Redis commands are points, of which kind, where their key is, and which
 * reply counts as empty. */
final class RedisCommands {

    record Command(String kind, Object key, String empty) {}

    record Table(String key_identifier, Map<String, Command> commands) {}

    static final Table TABLE = read();

    private RedisCommands() {}

    private static Table read() {
        try (InputStream table = RedisCommands.class.getResourceAsStream("/faultpoint/redis-commands.json")) {
            return Settings.JSON.copy().configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .readValue(table, Table.class);
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    static Pattern identifier(Map<String, Object> options) {
        return Pattern.compile(options.get("key_identifier") instanceof String pattern ? pattern : TABLE.key_identifier());
    }

    /** The locator of a command: its name and its key with identifiers templated, so that one key shape is one point. */
    static String locator(String name, String key, Pattern identifier) {
        return key == null ? name : name + " " + identifier.matcher(key).replaceAll("{}");
    }

    /** Whether a read's reply is empty by the command's rule; a client that turns a nil array into an empty
     * list gives an empty collection where Redis gave nil. */
    static boolean empty(Command command, Object reply) {
        return switch (command.empty()) {
            case "nil" -> reply == null || (reply instanceof Collection<?> values && values.isEmpty());
            case "empty_array" -> reply == null || (reply instanceof Collection<?> values && values.isEmpty())
                    || (reply instanceof Map<?, ?> entries && entries.isEmpty());
            case "empty_string" -> reply == null || (reply instanceof CharSequence text && text.isEmpty())
                    || (reply instanceof byte[] bytes && bytes.length == 0);
            case "zero" -> reply == null || Boolean.FALSE.equals(reply) || (reply instanceof Number number && number.longValue() == 0);
            case "all_nil" -> reply instanceof Collection<?> values && values.stream().allMatch(RedisCommands::absent);
            default -> false;
        };
    }

    /** A nil element, or a client's key-value holder without a value. */
    private static boolean absent(Object element) {
        if (element == null) {
            return true;
        }
        for (Method method : element.getClass().getMethods()) {
            if (method.getName().equals("hasValue") && method.getParameterCount() == 0) {
                try {
                    return Boolean.FALSE.equals(method.invoke(element));
                } catch (ReflectiveOperationException inaccessible) {
                    throw new IllegalStateException(inaccessible);
                }
            }
        }
        return false;
    }
}
