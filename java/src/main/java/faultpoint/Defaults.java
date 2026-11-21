package faultpoint;

import faultpoint.Core.ContextProvider;
import faultpoint.Core.Observation;
import faultpoint.Core.ObservationSink;
import faultpoint.Core.RuleSource;
import io.opentelemetry.api.baggage.Baggage;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Consumer;

/** The default rule source, observation sink and context provider. */
final class Defaults {

    private Defaults() {}

    static Thread daemon(String name, Runnable body) {
        Thread thread = new Thread(body, name);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    /** The rule set file named by FAULTPOINT_RULES, reloaded when it changes. */
    record FileRuleSource(Path path, long intervalMs) implements RuleSource {
        @Override
        public void start(Consumer<RuleSet> apply, Consumer<String> fail) {
            FileTime[] modified = {null};
            Runnable poll = () -> {
                try {
                    FileTime time = Files.getLastModifiedTime(path);
                    if (!time.equals(modified[0])) {
                        apply.accept(RuleSet.parse(Files.readString(path)));
                        modified[0] = time;
                    }
                } catch (IOException | IllegalArgumentException unusable) {
                    fail.accept(path + ": " + unusable.getMessage());
                }
            };
            poll.run();
            daemon("faultpoint-rules", () -> {
                while (true) {
                    try {
                        Thread.sleep(intervalMs);
                    } catch (InterruptedException interrupted) {
                        return;
                    }
                    poll.run();
                }
            });
        }
    }

    /** Observations aggregated per window and appended as JSON Lines, as spec/observation.schema.json defines. */
    static final class JsonlSink implements ObservationSink {
        /** The detail is a sorted copy, so that one detail is one key and its record lists the keys in order. */
        private record Key(String experiment, String point, String outcome, String scope, String rule,
                           SortedMap<String, String> detail) {}

        private static final class Tally {
            long count;
            double total;
            final List<String> exemplars = new ArrayList<>();
        }

        private final Path path;
        private final String service;
        private final String process = ManagementFactory.getRuntimeMXBean().getName();
        private final int exemplars;
        /** The share of traces whose ids are kept as exemplars, for hot library paths; counts stay exact. */
        private final double exemplarRate;

        /** Whether a trace is sampled, by its id, so that every process keeps or skips the same traces. */
        boolean sampled(String traceId) {
            return Math.floorMod(traceId.hashCode(), 10_000) < exemplarRate * 10_000;
        }
        private Map<Key, Tally> tally = new LinkedHashMap<>();
        private double start = System.currentTimeMillis() / 1000.0;

        JsonlSink(Path path, String service, Map<String, Object> options) {
            this.path = path;
            this.service = service;
            this.exemplars = ((Number) options.getOrDefault("exemplars", 5)).intValue();
            this.exemplarRate = ((Number) options.getOrDefault("exemplar_rate", 1)).doubleValue();
            long flushMs = (long) (((Number) options.getOrDefault("flush_seconds", 2)).doubleValue() * 1000);
            daemon("faultpoint-observations", () -> {
                while (true) {
                    try {
                        Thread.sleep(flushMs);
                    } catch (InterruptedException interrupted) {
                        return;
                    }
                    flush();
                }
            });
            Runtime.getRuntime().addShutdownHook(new Thread(this::flush));
        }

        @Override
        public synchronized void add(Observation observation) {
            Tally entry = tally.computeIfAbsent(new Key(observation.experiment(), observation.point(),
                    observation.outcome(), observation.scope(), observation.rule(), new TreeMap<>(observation.detail())),
                    ignored -> new Tally());
            entry.count += 1;
            entry.total += observation.quantity();
            if (observation.traceId() != null && entry.exemplars.size() < exemplars && sampled(observation.traceId())) {
                entry.exemplars.add(observation.traceId());
            }
        }

        @Override
        public void flush() {
            Map<Key, Tally> drained;
            double end = System.currentTimeMillis() / 1000.0;
            double windowStart;
            synchronized (this) {
                drained = tally;
                tally = new LinkedHashMap<>();
                windowStart = start;
                start = end;
            }
            if (drained.isEmpty()) {
                return;
            }
            var lines = new StringBuilder();
            drained.forEach((key, entry) -> {
                var record = new LinkedHashMap<String, Object>();
                record.put("experiment", key.experiment());
                record.put("service", service);
                record.put("process", process);
                record.put("start", windowStart);
                record.put("end", end);
                record.put("point", key.point());
                record.put("outcome", key.outcome());
                record.put("scope", key.scope());
                record.put("rule", key.rule());
                record.put("count", entry.count);
                record.put("total", entry.total);
                record.put("exemplars", entry.exemplars);
                record.put("detail", key.detail());
                try {
                    lines.append(Settings.JSON.writeValueAsString(record)).append('\n');
                } catch (IOException unserialisable) {
                    throw new UncheckedIOException(unserialisable);
                }
            });
            try {
                Files.writeString(path, lines, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException unwritable) {
                throw new UncheckedIOException(unwritable);
            }
        }
    }

    /** OpenTelemetry baggage and trace context of the current context. */
    static final class OtelContext implements ContextProvider {
        @Override
        public String baggage(String key) {
            return Baggage.current().getEntryValue(key);
        }

        @Override
        public String traceId() {
            SpanContext span = Span.current().getSpanContext();
            return span.isValid() ? span.getTraceId() : null;
        }
    }
}
