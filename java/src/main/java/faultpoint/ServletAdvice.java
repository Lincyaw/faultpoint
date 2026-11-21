package faultpoint;

import jakarta.servlet.AsyncListener;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
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
        entry = ServletBoundary.enter(http.getMethod(), http.getRequestURI(), headers,
                http.getDispatcherType() == DispatcherType.REQUEST);
        if (entry != null && entry.skips()) {
            answer.setStatus(entry.forcedStatus());
            return true;
        }
        return false;
    }

    /** The request ran; when nothing it did made its status known, the status it leaves is where fail_after is
     * decided, as long as it did not fail and its answer is not yet written. A request that went asynchronous is
     * observed when it completes. */
    @Advice.OnMethodExit(onThrowable = Throwable.class)
    static void exit(@Advice.Argument(0) ServletRequest request, @Advice.Argument(1) ServletResponse response,
                     @Advice.Local("entry") ServletBoundary.Entry entry, @Advice.Thrown Throwable thrown)
            throws ReflectiveOperationException {
        if (!(response instanceof HttpServletResponse answer)) {
            return;
        }
        boolean asynchronous = entry != null && request.isAsyncStarted();
        if (entry != null && thrown == null && !asynchronous && !answer.isCommitted()) {
            int status = answer.getStatus();
            int answered = ServletBoundary.answering(answer, status);
            if (answered != status) {
                answer.setStatus(answered);
            }
        }
        if (asynchronous) {
            request.getAsyncContext().addListener((AsyncListener) ServletBoundary.listener(entry, AsyncListener.class, request, answer));
        }
        ServletBoundary.exit(entry, answer.getStatus(), thrown, request.getAttribute(ServletBoundary.RESOLVED_EXCEPTION), asynchronous);
    }

    /** Inlined into setStatus(int) of HttpServletResponse implementations. */
    static final class Status {
        private Status() {}

        @Advice.OnMethodEnter
        static void enter(@Advice.This Object response, @Advice.Argument(value = 0, readOnly = false) int status)
                throws ReflectiveOperationException {
            status = ServletBoundary.answering(response, status);
        }
    }

    /** Inlined into sendError: an error answer is natural, and one after a replaced answer is dropped. */
    static final class Error {
        private Error() {}

        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
        static boolean enter(@Advice.This Object response, @Advice.Argument(0) int status) throws ReflectiveOperationException {
            return ServletBoundary.answering(response, status) != status;
        }
    }

    /** Inlined into sendRedirect(String): a redirect is a 302 answer, which fail_after may replace. */
    static final class Redirect {
        private Redirect() {}

        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
        static boolean enter(@Advice.This HttpServletResponse response) throws ReflectiveOperationException {
            int answered = ServletBoundary.answering(response, HttpServletResponse.SC_FOUND);
            if (answered != HttpServletResponse.SC_FOUND) {
                response.setStatus(answered);
                return true;
            }
            return false;
        }
    }

    /** Inlined into getOutputStream and flushBuffer: the body starts with the status the response has. */
    static final class Body {
        private Body() {}

        @Advice.OnMethodEnter
        static void enter(@Advice.This HttpServletResponse response) throws ReflectiveOperationException {
            int status = response.getStatus();
            int answered = ServletBoundary.answering(response, status);
            if (answered != status) {
                response.setStatus(answered);
            }
        }
    }

    /** Inlined into getWriter: the body starts with the status the response has, and a replaced answer's writer
     * writes nowhere. */
    static final class Writer {
        private Writer() {}

        @Advice.OnMethodEnter
        static void enter(@Advice.This HttpServletResponse response) throws ReflectiveOperationException {
            int status = response.getStatus();
            int answered = ServletBoundary.answering(response, status);
            if (answered != status) {
                response.setStatus(answered);
            }
        }

        @Advice.OnMethodExit
        static void exit(@Advice.Return(readOnly = false) PrintWriter writer) {
            if (ServletBoundary.replaced()) {
                writer = new PrintWriter(java.io.Writer.nullWriter());
            }
        }
    }

    /** Inlined into the header setters of HttpServletResponse implementations and the writes of ServletOutputStream
     * implementations: dropped once fail_after replaced the answer. */
    static final class Dropped {
        private Dropped() {}

        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
        static boolean enter() {
            return ServletBoundary.replaced();
        }
    }
}
