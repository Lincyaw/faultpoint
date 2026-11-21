package faultpoint;

import faultpoint.RuleSet.Rule;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import net.bytebuddy.matcher.ElementMatchers;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.Statement;
import net.sf.jsqlparser.statement.UnsupportedStatement;
import net.sf.jsqlparser.statement.select.ParenthesedSelect;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.Select;
import net.sf.jsqlparser.statement.select.WithItem;
import net.sf.jsqlparser.util.TablesNamesFinder;

/** The store_read and store_write points of every JDBC statement a driver executes, whoever calls it:
 * JdbcTemplate, a connection pool, JPA or the application. Advice on the implementations of
 * java.sql.Statement and java.sql.Connection calls into this class. */
public final class Jdbc {

    private record Kind(String kind, String locator) {}

    private static final Map<String, Kind> STATEMENTS = new ConcurrentHashMap<>();
    /** The SQL of each prepared statement, which JDBC does not expose. */
    private static final Map<Object, String> PREPARED = Collections.synchronizedMap(new WeakHashMap<>());
    /** A pool's statement proxy calls the driver's statement; only the outermost execution is a point. */
    private static final ThreadLocal<int[]> DEPTH = ThreadLocal.withInitial(() -> new int[1]);
    private static final String BATCH = "-#batch";
    /** The locators statementPoint makes, and the batch locator. */
    private static final Pattern STATEMENT_LOCATOR = Pattern.compile("[^ ]+#([0-9a-f]{8}|batch)");
    private static final Pattern SQLSTATE = Pattern.compile("[0-9A-Z]{5}");

    private Jdbc() {}

    /** The tables a statement touches and whether it writes: TablesNamesFinder's walk, which also enters a WITH item
     * that inserts, updates or deletes and takes the table a query selects INTO, both of which write. The name of a
     * WITH item is not a table. */
    static final class Touched extends TablesNamesFinder<Void> {
        private final Set<String> named = new HashSet<>();
        private boolean writes;

        @Override
        public <S> Void visit(WithItem<?> withItem, S context) {
            named.add(withItem.getAliasName());
            if (withItem.getParenthesedStatement() instanceof ParenthesedSelect) {
                return super.visit(withItem, context);
            }
            writes = true;
            return withItem.getParenthesedStatement().accept(this, context);
        }

        @Override
        public <S> Void visit(PlainSelect select, S context) {
            super.visit(select, context);
            if (select.getIntoTables() != null) {
                writes = true;
                select.getIntoTables().forEach(table -> visit(table, context));
            }
            return null;
        }

        Set<String> tables(Statement statement) {
            Set<String> tables = new TreeSet<>(getTables(statement));
            tables.removeAll(named);
            return tables;
        }

        boolean writes() {
            return writes;
        }
    }

    /** The kind and locator of a statement: a query that writes through neither a WITH item nor INTO is read and
     * anything else written, the tables it touches and the hash of its normalised text. A statement the parser does
     * not understand is written, since the parser recognises every query form a driver is sent. */
    static Kind statementPoint(String sql) {
        return STATEMENTS.computeIfAbsent(sql, text -> {
            List<Statement> statements = new ArrayList<>();
            try {
                statements.addAll(CCJSqlParserUtil.parseStatements(text, parser -> parser.withUnsupportedStatements()));
            } catch (JSQLParserException unparsable) {
                statements.add(new UnsupportedStatement(text, List.of()));
            }
            boolean reads = !statements.isEmpty();
            var tables = new TreeSet<String>();
            var shape = new StringBuilder();
            for (Statement statement : statements) {
                if (statement instanceof UnsupportedStatement) {
                    reads = false;
                } else {
                    Touched touched = new Touched();
                    tables.addAll(touched.tables(statement));
                    reads = reads && statement instanceof Select && !touched.writes();
                }
                shape.append(statement instanceof UnsupportedStatement ? text.strip() : statement.toString()).append(';');
            }
            String table = tables.isEmpty() ? "-" : String.join("+", tables);
            return new Kind(reads ? "store_read" : "store_write", table + "#" + Placement.digest(shape.toString()));
        });
    }

    /** One outermost execution under its rule; injected is the error a fail rule answers with, or null. */
    public record Execution(String point, String kind, Rule rule, long started, SQLException injected) {
        String action() {
            return rule == null ? "" : rule.kind();
        }

        double elapsed() {
            return (System.nanoTime() - started) / 1e6;
        }
    }

    /** What the exit advice returns or throws in place of the driver's own result. */
    public record Outcome(Object returned, Throwable thrown) {}

    public static void prepared(Object statement, Object sql) {
        if (statement != null && sql instanceof String text) {
            PREPARED.put(statement, text);
        }
    }

    /** Enter a statement execution; a fail rule's error is made here, so that the driver does not run and the exit
     * advice throws it. */
    public static Object enter(Object statement, Object[] arguments) throws SQLException {
        long started = System.nanoTime();
        int[] depth = DEPTH.get();
        depth[0] += 1;
        Core core = Core.current();
        if (depth[0] > 1 || !core.enabled()) {
            return null;
        }
        String sql = arguments.length > 0 && arguments[0] instanceof String text ? text : PREPARED.get(statement);
        Kind kind = sql == null && !(statement instanceof java.sql.PreparedStatement) ? new Kind("store_write", BATCH)
                : statementPoint(requireSql(core, sql));
        String point = RuleSet.pointId(core.settings.service(), kind.kind(), kind.locator());
        Rule rule = core.decide(point, Core.ACTS_BEFORE);
        // The query timeout cuts a rule's wait short as it cuts a slow server: the driver cancels the statement at the
        // server, so that it does not run, and fails as it does then.
        boolean cut = rule != null && Points.holdWithin(core, rule, queryTimeout(statement));
        SQLException injected = cut ? queryTimedOut(statement) : rule != null && rule.kind().equals("fail")
                ? injectedError(statement, rule, "faultpoint: injected store failure") : null;
        if (injected != null) {
            core.observe(point, "error", 0, Points.since(started), rule, failureDetail(injected, false));
        }
        return new Execution(point, kind.kind(), rule, started, injected);
    }

    /** A statement's query timeout, which the driver counts from sending it; none when the statement cannot tell, as a
     * closed one, whose execution then fails on its own. */
    private static Duration queryTimeout(Object statement) {
        try {
            return Duration.ofSeconds(((java.sql.Statement) statement).getQueryTimeout());
        } catch (SQLException unknown) {
            return null;
        }
    }

    /** The error of a statement its query timeout cancelled: PostgreSQL's 57014 for its driver, which cancels the
     * statement at the server, and SQLTimeoutException, which JDBC names for it, otherwise. */
    static SQLException queryTimedOut(Object statement) throws SQLException {
        SQLException postgres = postgresError(statement, "57014", "canceling statement due to user request");
        return postgres != null ? postgres : new SQLTimeoutException("faultpoint: query timed out");
    }

    /** The error a fail or fail_after rule raises. With a code it is the driver's own error for a server error of that
     * SQLSTATE: PSQLException made from the fields PostgreSQL sends when the statement is PostgreSQL's driver, otherwise
     * an SQLException with that state. Without one it is a connection failure, 08006. */
    static SQLException injectedError(Object statement, Rule rule, String message) throws SQLException {
        String code = rule.text("code");
        if (code == null) {
            return new SQLException(message, "08006");
        }
        SQLException postgres = postgresError(statement, code, message);
        return postgres != null ? postgres : new SQLException(message, code);
    }

    /** PostgreSQL's driver error for a server error of a SQLSTATE and message, made from the fields PostgreSQL sends, or
     * null when the statement is another driver's. */
    static SQLException postgresError(Object statement, String code, String message) throws SQLException {
        ClassLoader driver = statement.getClass().getClassLoader();
        Class<?> postgresStatement;
        try {
            postgresStatement = Class.forName("org.postgresql.PGStatement", false, driver);
        } catch (ClassNotFoundException absent) {
            return null;
        }
        if (!((java.sql.Statement) statement).isWrapperFor(postgresStatement)) {
            return null;
        }
        try {
            Object fields = Class.forName("org.postgresql.util.ServerErrorMessage", true, driver).getConstructor(String.class)
                    .newInstance("SERROR\0VERROR\0C" + code + "\0M" + message + "\0");
            return (SQLException) Class.forName("org.postgresql.util.PSQLException", true, driver)
                    .getConstructor(fields.getClass()).newInstance(fields);
        } catch (ReflectiveOperationException unavailable) {
            throw new IllegalStateException("faultpoint: cannot make PostgreSQL's driver error", unavailable);
        }
    }

    /** Whether a locator has the shape statementPoint makes, which is the points this plugin serves. */
    static boolean statementLocator(String locator) {
        return STATEMENT_LOCATOR.matcher(locator).matches();
    }

    /** Why a rule at a statement point cannot be obeyed: a code that is not a SQLSTATE, which no driver reports. */
    static String refusal(Rule rule) {
        String code = rule.text("code");
        boolean statementPoint = (rule.pointKind().equals("store_read") || rule.pointKind().equals("store_write"))
                && statementLocator(rule.locator());
        return code == null || !statementPoint || SQLSTATE.matcher(code).matches() ? null
                : "code " + code + " at " + rule.point() + " is not a SQLSTATE, five digits or upper-case letters";
    }

    /** A failed statement's exception type, for an SQLException its SQLSTATE, and whether it had reached the server,
     * when that is known. */
    static Map<String, String> failureDetail(Throwable failure, Boolean sent) {
        Map<String, String> detail = new HashMap<>(Map.of("error", failure.getClass().getName()));
        if (failure instanceof SQLException sql && sql.getSQLState() != null) {
            detail.put("code", sql.getSQLState());
        }
        if (sent != null) {
            detail.put("sent", sent.toString());
        }
        return detail;
    }

    /** Whether a statement that failed of itself had reached the server: it had when the server reported the error, as
     * PostgreSQL's driver keeps the server's message, its query timeout included, and it had not when no connection
     * could be made, SQLSTATE 08001; null when the failure does not tell. */
    static Boolean reached(Throwable failure) {
        if (failure instanceof SQLException sql && "08001".equals(sql.getSQLState())) {
            return false;
        }
        if (!failure.getClass().getName().equals("org.postgresql.util.PSQLException")) {
            return null;
        }
        try {
            return failure.getClass().getMethod("getServerErrorMessage").invoke(failure) != null ? Boolean.TRUE : null;
        } catch (ReflectiveOperationException unreadable) {
            throw Core.internalError(unreadable);
        }
    }

    private static String requireSql(Core core, String sql) {
        if (sql == null) {
            core.abort("a prepared statement ran whose SQL the agent did not see prepared");
        }
        return sql;
    }

    /** Whether the driver is skipped: for a dropped write, which returns one row affected without reaching the database,
     * and for a fail rule's error; null runs it. */
    public static Object skipped(Object execution) {
        return execution instanceof Execution running && (running.action().equals("drop") || running.injected() != null)
                ? Boolean.TRUE : null;
    }

    private static Object droppedResult(Class<?> type) {
        if (type == int.class || type == Integer.class) {
            return 1;
        }
        if (type == long.class || type == Long.class) {
            return 1L;
        }
        if (type == boolean.class) {
            return false;
        }
        return type == long[].class ? new long[] {1} : new int[] {1};
    }

    public static Outcome exit(Object execution, Object statement, Method method, Object[] arguments, Object skipped,
                               Object returned, Throwable thrown) throws SQLException {
        DEPTH.get()[0] -= 1;
        if (!(execution instanceof Execution running)) {
            return new Outcome(returned, thrown);
        }
        if (running.injected() != null) {
            return new Outcome(returned, running.injected());
        }
        Core core = Core.current();
        if (skipped != null) {
            core.observe(running.point(), "ok", 1, running.elapsed(), running.rule(), Map.of());
            return new Outcome(droppedResult(method.getReturnType()), null);
        }
        if (thrown == null && running.action().equals("duplicate")) {
            DEPTH.get()[0] += 1;
            try {
                returned = method.invoke(statement, arguments);
            } catch (InvocationTargetException failure) {
                thrown = failure.getCause();
            } catch (IllegalAccessException inaccessible) {
                throw Core.internalError(inaccessible);
            } finally {
                DEPTH.get()[0] -= 1;
            }
        }
        if (thrown != null) {
            core.observe(running.point(), "error", running.elapsed(), running.elapsed(), running.rule(), failureDetail(thrown, reached(thrown)));
            return new Outcome(returned, thrown);
        }
        Rule replacing = core.decide(running.point(), Core.ACTS_AFTER);
        if (replacing != null) {
            SQLException injected = injectedError(statement, replacing, "faultpoint: store failed after the statement ran");
            core.observe(running.point(), "error", running.elapsed(), running.elapsed(), replacing, failureDetail(injected, true));
            return new Outcome(returned, injected);
        }
        if (running.kind().equals("store_write")) {
            core.observe(running.point(), "ok", affected(returned), running.elapsed(), running.rule(), Map.of());
            return new Outcome(returned, null);
        }
        if (returned instanceof ResultSet rows) {
            return new Outcome(observed(rows, running, running.elapsed()), null);
        }
        core.observe(running.point(), Boolean.TRUE.equals(returned) ? "rows" : "empty", 0, running.elapsed(), running.rule(), Map.of());
        return new Outcome(returned, null);
    }

    private static double affected(Object returned) {
        if (returned instanceof Number count) {
            return count.doubleValue();
        }
        if (returned instanceof int[] counts) {
            return java.util.Arrays.stream(counts).sum();
        }
        return returned instanceof long[] counts ? java.util.Arrays.stream(counts).sum() : 0;
    }

    /** A result set that counts its rows and observes the read once it is exhausted or closed, with the elapsed time
     * of the statement until the driver returned it; under an empty rule it yields no row. */
    private static ResultSet observed(ResultSet rows, Execution execution, double elapsed) {
        InvocationHandler handler = new InvocationHandler() {
            int seen;
            boolean recorded;

            /** The driver's result set answers, and its errors reach the application; counting the rows is the agent's
             * own work, whose error stops the process. */
            @Override
            public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
                Object result;
                try {
                    result = method.getName().equals("next") && execution.action().equals("empty") ? Boolean.FALSE
                            : method.invoke(rows, arguments);
                } catch (InvocationTargetException failure) {
                    throw failure.getCause();
                } catch (IllegalAccessException inaccessible) {
                    throw Core.internalError(inaccessible);
                }
                try {
                    if (method.getName().equals("next")) {
                        if ((Boolean) result) {
                            seen += 1;
                        } else {
                            record();
                        }
                    }
                    if (method.getName().equals("close")) {
                        record();
                    }
                } catch (RuntimeException | Error unexpected) {
                    throw Core.internalError(unexpected);
                }
                return result;
            }

            void record() {
                if (!recorded) {
                    recorded = true;
                    Core.current().observe(execution.point(), seen > 0 ? "rows" : "empty", seen, elapsed, execution.rule(), Map.of());
                }
            }
        };
        return (ResultSet) Proxy.newProxyInstance(ResultSet.class.getClassLoader(), new Class<?>[] {ResultSet.class}, handler);
    }

    public static final class JdbcPlugin implements Plugin {
        static final List<String> EXECUTIONS = List.of("execute", "executeQuery", "executeUpdate", "executeLargeUpdate",
                "executeBatch", "executeLargeBatch");

        @Override
        public String name() {
            return "jdbc";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            installation.core().declare(Map.of(
                    "store_read", List.of("fail", "empty", "delay", "crash"),
                    "store_write", List.of("fail", "fail_after", "drop", "duplicate", "delay", "crash")), Jdbc::statementLocator);
            installation.core().check(Jdbc::refusal);
            // Classifying a statement now loads the parser while the agent starts, not while the application runs its first statement.
            statementPoint("SELECT a FROM b WHERE c = ?");
            installation.advise(
                    ElementMatchers.hasSuperType(ElementMatchers.named("java.sql.Statement")).and(ElementMatchers.not(ElementMatchers.isInterface())),
                    new Advices.Method(ElementMatchers.isPublic().and(ElementMatchers.not(ElementMatchers.isAbstract()))
                            .and(ElementMatchers.namedOneOf(EXECUTIONS.toArray(String[]::new))), "faultpoint.JdbcAdvice"));
            installation.advise(
                    ElementMatchers.hasSuperType(ElementMatchers.named("java.sql.Connection")).and(ElementMatchers.not(ElementMatchers.isInterface())),
                    new Advices.Method(ElementMatchers.isPublic().and(ElementMatchers.not(ElementMatchers.isAbstract()))
                            .and(ElementMatchers.namedOneOf("prepareStatement", "prepareCall"))
                            .and(ElementMatchers.takesArgument(0, String.class)), "faultpoint.JdbcAdvice$Prepare"));
        }
    }
}
