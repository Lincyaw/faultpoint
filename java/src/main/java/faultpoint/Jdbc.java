package faultpoint;

import faultpoint.RuleSet.Rule;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.select.Select;
import net.sf.jsqlparser.util.TablesNamesFinder;

/** The store_read and store_write points of JDBC calls in the configured packages, whose call sites
 * the placement routes here. */
public final class Jdbc {

    private record Kind(String kind, String locator) {}

    private static final Map<String, Kind> STATEMENTS = new ConcurrentHashMap<>();
    /** The SQL of each prepared statement, which JDBC does not expose. */
    private static final Map<PreparedStatement, String> PREPARED = Collections.synchronizedMap(new WeakHashMap<>());

    private Jdbc() {}

    /** The kind and locator of a statement: the tables it touches and the hash of its normalised text. */
    static Kind statementPoint(String sql) {
        return STATEMENTS.computeIfAbsent(sql, text -> {
            try {
                var statement = CCJSqlParserUtil.parse(text);
                var tables = new TreeSet<>(TablesNamesFinder.findTables(text));
                String kind = statement instanceof Select ? "store_read" : "store_write";
                String table = tables.isEmpty() ? "-" : String.join("+", tables);
                return new Kind(kind, table + "#" + Placement.digest(statement.toString()));
            } catch (JSQLParserException unparsable) {
                throw new IllegalArgumentException("faultpoint: cannot parse a statement: " + text, unparsable);
            }
        });
    }

    private record Execution(String point, Rule rule, long started) {
        String kind() {
            return rule == null ? "" : rule.kind();
        }

        double elapsed() {
            return (System.nanoTime() - started) / 1e6;
        }
    }

    private static Execution begin(String sql) throws SQLException {
        Core core = Core.current();
        Kind kind = statementPoint(sql);
        String point = RuleSet.pointId(core.settings.service(), kind.kind(), kind.locator());
        Rule rule = core.decide(point);
        if (rule != null) {
            Points.hold(core, rule);
        }
        Execution execution = new Execution(point, rule, System.nanoTime());
        if (execution.kind().equals("fail")) {
            core.observe(point, "error", execution.elapsed(), rule);
            throw new SQLException("faultpoint: injected store failure", "08006");
        }
        return execution;
    }

    private interface Run<T> {
        T run() throws SQLException;
    }

    /** A result set that counts its rows and observes the read once it is exhausted or closed; under an
     * empty rule it yields no row. */
    private static ResultSet observed(ResultSet rows, Execution execution) {
        InvocationHandler handler = new InvocationHandler() {
            int seen;
            boolean recorded;

            @Override
            public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] arguments) throws Throwable {
                if (method.getName().equals("next") && execution.kind().equals("empty")) {
                    record();
                    return false;
                }
                Object result;
                try {
                    result = method.invoke(rows, arguments);
                } catch (InvocationTargetException failure) {
                    throw failure.getCause();
                }
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
                return result;
            }

            void record() {
                if (!recorded) {
                    recorded = true;
                    Core.current().observe(execution.point(), seen > 0 ? "rows" : "empty", seen, execution.rule());
                }
            }
        };
        return (ResultSet) Proxy.newProxyInstance(ResultSet.class.getClassLoader(), new Class<?>[] {ResultSet.class}, handler);
    }

    private static ResultSet query(String sql, Run<ResultSet> run) throws SQLException {
        if (!Core.current().enabled()) {
            return run.run();
        }
        Execution execution = begin(sql);
        try {
            return observed(run.run(), execution);
        } catch (SQLException failure) {
            Core.current().observe(execution.point(), "error", execution.elapsed(), execution.rule());
            throw failure;
        }
    }

    private static int update(String sql, Run<Integer> run) throws SQLException {
        Core core = Core.current();
        if (!core.enabled()) {
            return run.run();
        }
        Execution execution = begin(sql);
        if (execution.kind().equals("drop")) {
            core.observe(execution.point(), "ok", 1, execution.rule());
            return 1;
        }
        int affected;
        try {
            affected = run.run();
            if (execution.kind().equals("duplicate")) {
                affected = run.run();
            }
        } catch (SQLException failure) {
            core.observe(execution.point(), "error", execution.elapsed(), execution.rule());
            throw failure;
        }
        if (execution.kind().equals("fail_after")) {
            core.observe(execution.point(), "error", execution.elapsed(), execution.rule());
            throw new SQLException("faultpoint: store failed after the statement ran", "08006");
        }
        core.observe(execution.point(), "ok", affected, execution.rule());
        return affected;
    }

    /** execute() may read or write; a read through it is observed without its row count. */
    private static boolean execute(String sql, Run<Boolean> run) throws SQLException {
        if (statementPoint(sql).kind().equals("store_write")) {
            int[] produced = {0};
            update(sql, () -> {
                produced[0] = run.run() ? 1 : 0;
                return 0;
            });
            return produced[0] == 1;
        }
        boolean[] produced = {false};
        query(sql, () -> {
            produced[0] = run.run();
            return null;
        });
        return produced[0];
    }

    public static PreparedStatement prepareStatement(Connection connection, String sql) throws SQLException {
        PreparedStatement statement = connection.prepareStatement(sql);
        PREPARED.put(statement, sql);
        return statement;
    }

    public static ResultSet executeQuery(Statement statement, String sql) throws SQLException {
        return query(sql, () -> statement.executeQuery(sql));
    }

    public static int executeUpdate(Statement statement, String sql) throws SQLException {
        return update(sql, () -> statement.executeUpdate(sql));
    }

    public static boolean execute(Statement statement, String sql) throws SQLException {
        return execute(sql, () -> statement.execute(sql));
    }

    private static String preparedSql(PreparedStatement statement) {
        String sql = PREPARED.get(statement);
        if (sql == null) {
            throw new IllegalStateException("faultpoint: a prepared statement was created outside the configured packages");
        }
        return sql;
    }

    public static ResultSet executeQuery(PreparedStatement statement) throws SQLException {
        return query(preparedSql(statement), statement::executeQuery);
    }

    public static int executeUpdate(PreparedStatement statement) throws SQLException {
        return update(preparedSql(statement), statement::executeUpdate);
    }

    public static boolean execute(PreparedStatement statement) throws SQLException {
        return execute(preparedSql(statement), statement::execute);
    }

    public static final class JdbcPlugin implements Plugin {
        static final Set<String> STATEMENTS = Set.of("java/sql/Statement", "java/sql/PreparedStatement", "java/sql/CallableStatement");
        static final Set<String> PREPARED = Set.of("java/sql/PreparedStatement", "java/sql/CallableStatement");

        @Override
        public String name() {
            return "jdbc";
        }

        @Override
        public void install(Installation installation, Map<String, Object> options) {
            installation.core().declare(Map.of(
                    "store_read", List.of("fail", "empty", "delay", "crash"),
                    "store_write", List.of("fail", "fail_after", "drop", "duplicate", "delay", "crash")));
            Placement placement = installation.placement();
            placement.replaceCalls(Set.of("java/sql/Connection"), "prepareStatement",
                    "(Ljava/lang/String;)Ljava/sql/PreparedStatement;", Jdbc.class, "prepareStatement",
                    "(Ljava/sql/Connection;Ljava/lang/String;)Ljava/sql/PreparedStatement;");
            placement.replaceCalls(STATEMENTS, "executeQuery", "(Ljava/lang/String;)Ljava/sql/ResultSet;", Jdbc.class,
                    "executeQuery", "(Ljava/sql/Statement;Ljava/lang/String;)Ljava/sql/ResultSet;");
            placement.replaceCalls(STATEMENTS, "executeUpdate", "(Ljava/lang/String;)I", Jdbc.class,
                    "executeUpdate", "(Ljava/sql/Statement;Ljava/lang/String;)I");
            placement.replaceCalls(STATEMENTS, "execute", "(Ljava/lang/String;)Z", Jdbc.class,
                    "execute", "(Ljava/sql/Statement;Ljava/lang/String;)Z");
            placement.replaceCalls(PREPARED, "executeQuery", "()Ljava/sql/ResultSet;", Jdbc.class,
                    "executeQuery", "(Ljava/sql/PreparedStatement;)Ljava/sql/ResultSet;");
            placement.replaceCalls(PREPARED, "executeUpdate", "()I", Jdbc.class,
                    "executeUpdate", "(Ljava/sql/PreparedStatement;)I");
            placement.replaceCalls(PREPARED, "execute", "()Z", Jdbc.class,
                    "execute", "(Ljava/sql/PreparedStatement;)Z");
        }
    }
}
