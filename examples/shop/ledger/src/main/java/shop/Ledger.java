package shop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;

/** Charges accounts for orders. */
public class Ledger extends HttpServlet {

    static final ObjectMapper JSON = new ObjectMapper();

    static final class InsufficientFunds extends Exception {
        InsufficientFunds(String account) {
            super("insufficient funds in " + account);
        }
    }

    private final Connection connection;

    Ledger(Connection connection) {
        this.connection = connection;
    }

    synchronized void charge(String account, long amount) throws SQLException, InsufficientFunds {
        PreparedStatement select = connection.prepareStatement("SELECT balance FROM accounts WHERE id = ?");
        select.setString(1, account);
        long balance;
        try (ResultSet rows = select.executeQuery()) {
            if (!rows.next()) {
                throw new IllegalStateException("unknown account " + account);
            }
            balance = rows.getLong(1);
        }
        if (balance < amount) {
            throw new InsufficientFunds(account);
        }
        PreparedStatement update = connection.prepareStatement("UPDATE accounts SET balance = balance - ? WHERE id = ?");
        update.setLong(1, amount);
        update.setString(2, account);
        update.executeUpdate();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        JsonNode body = JSON.readTree(request.getInputStream());
        try {
            charge(body.get("account").asText(), body.get("amount").asLong());
            response.setStatus(200);
        } catch (InsufficientFunds declined) {
            response.setStatus(402);
            response.getWriter().print(declined.getMessage());
        } catch (SQLException | IllegalStateException failure) {
            response.setStatus(500);
            response.getWriter().print(failure.getMessage());
        }
    }

    public static void main(String[] arguments) throws Exception {
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + System.getenv("LEDGER_DATABASE"));
        Server server = new Server(Integer.parseInt(System.getenv().getOrDefault("PORT", "8084")));
        ServletContextHandler context = new ServletContextHandler();
        context.addServlet(new ServletHolder(new Ledger(connection)), "/charge");
        server.setHandler(context);
        server.start();
        System.out.println("ledger listening");
        server.join();
    }
}
