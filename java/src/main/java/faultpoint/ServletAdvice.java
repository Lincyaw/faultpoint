package faultpoint;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import net.bytebuddy.asm.Advice;

/** Inlined into HttpServlet.service(ServletRequest, ServletResponse); never loaded by the agent, so the
 * servlet types resolve in the servlet's own class loader. */
final class ServletAdvice {

    private ServletAdvice() {}

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    static boolean enter(@Advice.Argument(0) ServletRequest request, @Advice.Argument(1) ServletResponse response,
                         @Advice.Local("entry") ServletBoundary.Entry entry) {
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse answer)) {
            return false;
        }
        Map<String, String> headers = new HashMap<>();
        for (String name : Collections.list(http.getHeaderNames())) {
            headers.put(name.toLowerCase(), http.getHeader(name));
        }
        entry = ServletBoundary.enter(http.getMethod(), http.getRequestURI(), headers);
        if (entry != null && entry.skips()) {
            answer.setStatus(entry.forcedStatus());
            return true;
        }
        return false;
    }

    /** A fail_after request ran; its answer is replaced unless it already left. */
    @Advice.OnMethodExit(onThrowable = Throwable.class)
    static void exit(@Advice.Argument(1) ServletResponse response, @Advice.Local("entry") ServletBoundary.Entry entry,
                     @Advice.Thrown Throwable thrown) {
        if (!(response instanceof HttpServletResponse answer)) {
            return;
        }
        if (entry != null && entry.forcedStatus() != 0 && !answer.isCommitted()) {
            answer.resetBuffer();
            answer.setStatus(entry.forcedStatus());
        }
        ServletBoundary.exit(entry, entry != null && entry.forcedStatus() != 0 ? entry.forcedStatus() : answer.getStatus(),
                thrown != null);
    }
}
