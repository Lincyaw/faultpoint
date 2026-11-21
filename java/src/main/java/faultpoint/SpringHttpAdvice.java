package faultpoint;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;

/** Inlined into ClientHttpRequest#execute implementations; never loaded by the agent. */
final class SpringHttpAdvice {

    private SpringHttpAdvice() {}

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    static Object enter(@Advice.This ClientHttpRequest request, @Advice.Local("call") Object call) throws IOException {
        Map<String, String> headers = new HashMap<>();
        call = SpringHttp.enter(request.getMethod().name(), request.getURI(), headers);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.getHeaders().set(header.getKey(), header.getValue());
        }
        return SpringHttp.answered(call, ClientHttpResponse.class);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    static void exit(@Advice.Local("call") Object call, @Advice.Enter Object answered,
                     @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response,
                     @Advice.Thrown(readOnly = false) Throwable thrown) throws IOException {
        if (answered != null) {
            response = answered;
        }
        int status = thrown == null && response != null ? ((ClientHttpResponse) response).getStatusCode().value() : 0;
        Object replacement = SpringHttp.exit(call, ClientHttpResponse.class, answered, status, thrown);
        if (replacement != null) {
            ((ClientHttpResponse) response).close();
        }
        if (replacement instanceof Throwable failure) {
            thrown = failure;
            response = null;
        } else if (replacement != null) {
            response = replacement;
        }
    }

    /** Inlined into executeInternal(HttpHeaders, Body) of the streaming ClientHttpRequest implementations, which
     * every request factory of Spring 6.1 and later uses to write a body. */
    static final class Streaming {
        private Streaming() {}

        @Advice.OnMethodEnter
        static void enter(@Advice.Argument(value = 1, readOnly = false) StreamingHttpOutputMessage.Body body) {
            body = (StreamingHttpOutputMessage.Body) SpringHttp.watched(body, StreamingHttpOutputMessage.Body.class);
        }
    }
}
