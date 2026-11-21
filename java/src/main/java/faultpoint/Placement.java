package faultpoint;

import java.lang.instrument.ClassFileTransformer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

/** Rewrites the classes of the configured packages: places branch, check, loop and clock points and
 * replaces the call sites boundary plugins registered. The agent and the offline scan share it, so
 * point ids agree. */
public final class Placement implements ClassFileTransformer {

    static final String POINTS = "faultpoint/Points";
    static final int CODE_WIDTH = 120;

    /** One point of the manifest, as spec/manifest.schema.json defines. */
    public record PointEntry(String id, String kind, String file, int line, String function, String code) {}

    /** A call site rewritten to a static helper whose first parameter is the receiver. */
    record CallSite(String name, String descriptor, String helperOwner, String helperName, String helperDescriptor) {}

    /** Code that never gets points: the JDK, the agent and what it observes through, and logging. */
    static final List<String> ALWAYS_EXCLUDED = List.of("java/", "javax/", "jdk/", "sun/", "com/sun/", "faultpoint/",
            "io/opentelemetry/", "org/slf4j/", "ch/qos/logback/", "org/apache/logging/", "org/apache/commons/logging/");
    static final java.util.regex.Pattern JAR_VERSION = java.util.regex.Pattern.compile("([^/!]+?)-(\\d[^/!]*)\\.jar(!/)?$");

    /** Where a class's points go: the prefix of their locators, and the kinds allowed there (null: every kind).
     * Business code has an empty prefix and also gets the boundary plugins' call sites. */
    record Target(String prefix, Set<String> kinds, boolean business) {
        boolean allows(String kind) {
            return kinds == null || kinds.contains(kind);
        }
    }

    private final String service;
    private final List<String> packages;
    private final Settings.Placement switches;
    private final List<String> excluded;
    private final Map<String, List<CallSite>> callSites = new HashMap<>();
    private final List<PointEntry> points = new ArrayList<>();
    private boolean placesPoints;

    public Placement(String service, List<String> packages, Settings.Placement switches) {
        this.service = service;
        this.packages = packages.stream().map(name -> name.replace('.', '/')).toList();
        this.switches = switches;
        this.excluded = java.util.stream.Stream.concat(ALWAYS_EXCLUDED.stream(),
                switches.exclude().stream().map(name -> name.replace('.', '/'))).toList();
    }

    /** The version of the jar a class comes from, by the artifact-version.jar convention, which the offline scan
     * reads from the same jar names; "unknown" when the name carries none. */
    static String version(String location) {
        var matched = JAR_VERSION.matcher(location == null ? "" : location);
        return matched.find() ? matched.group(2) : "unknown";
    }

    /** Where the points of a class go, or null when it gets none. */
    Target target(String internalName, String location) {
        if (internalName == null || excluded.stream().anyMatch(internalName::startsWith)) {
            return null;
        }
        if (packages.stream().anyMatch(internalName::startsWith)) {
            return new Target("", null, true);
        }
        for (Settings.ScopeEntry entry : switches.scope()) {
            if (internalName.startsWith(entry.include().replace('.', '/'))) {
                return new Target(entry.include() + "@" + version(location) + "/",
                        entry.kinds() == null ? null : Set.copyOf(entry.kinds()), false);
            }
        }
        return null;
    }

    void placePoints() {
        placesPoints = true;
    }

    /** Rewrite calls to `owner.name descriptor` into calls to a static helper, for every listed owner. */
    public void replaceCalls(Set<String> owners, String name, String descriptor, Class<?> helper, String helperName,
                             String helperDescriptor) {
        String helperOwner = helper.getName().replace('.', '/');
        for (String owner : owners) {
            callSites.computeIfAbsent(owner, ignored -> new ArrayList<>())
                    .add(new CallSite(name, descriptor, helperOwner, helperName, helperDescriptor));
        }
    }

    List<PointEntry> points() {
        return points;
    }

    @Override
    public byte[] transform(ClassLoader loader, String internalName, Class<?> redefined, ProtectionDomain domain,
                            byte[] classfile) {
        String location = domain == null || domain.getCodeSource() == null || domain.getCodeSource().getLocation() == null
                ? null : domain.getCodeSource().getLocation().toString();
        Target target = target(internalName, location);
        if (target == null) {
            return null;
        }
        try {
            return rewrite(classfile, loader, target);
        } catch (RuntimeException failure) {
            System.err.println("faultpoint: cannot rewrite " + internalName + ": " + failure);
            return null;
        }
    }

    byte[] rewrite(byte[] classfile, ClassLoader loader, Target target) {
        var node = new ClassNode();
        new ClassReader(classfile).accept(node, ClassReader.SKIP_FRAMES);
        var declarations = new Declarations(loader == null ? ClassLoader.getSystemClassLoader() : loader);
        for (MethodNode method : node.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE)) == 0) {
                new MethodPlacer(node.name, method, declarations, target).place();
            }
        }
        var writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES) {
            @Override
            protected ClassLoader getClassLoader() {
                return loader == null ? ClassLoader.getSystemClassLoader() : loader;
            }

            // Frames merge types the agent may be unable to load while the class is defined; Object keeps those frames verifiable.
            @Override
            protected String getCommonSuperClass(String first, String second) {
                try {
                    return super.getCommonSuperClass(first, second);
                } catch (RuntimeException | LinkageError unknown) {
                    return "java/lang/Object";
                }
            }
        };
        node.accept(writer);
        return writer.toByteArray();
    }

    static String digest(String text) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 4);
        } catch (NoSuchAlgorithmException missing) {
            throw new IllegalStateException(missing);
        }
    }

    private static boolean conditional(AbstractInsnNode instruction) {
        int opcode = instruction.getOpcode();
        return instruction instanceof JumpInsnNode && opcode != Opcodes.GOTO && opcode != Opcodes.JSR;
    }

    private static boolean transfers(AbstractInsnNode instruction) {
        int opcode = instruction.getOpcode();
        return instruction instanceof JumpInsnNode || opcode == Opcodes.ATHROW || opcode == Opcodes.TABLESWITCH
                || opcode == Opcodes.LOOKUPSWITCH || (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN);
    }

    /** The checked exceptions methods declare, read from the class files a class loader finds, so that a call
     * point throws only what its callee may throw. */
    static final class Declarations {
        private final ClassLoader loader;
        private final Map<String, ClassNode> classes = new HashMap<>();

        Declarations(ClassLoader loader) {
            this.loader = loader;
        }

        /** The class file of a type without code, or null when the loader cannot find it. */
        ClassNode type(String internalName) {
            return classes.computeIfAbsent(internalName, name -> {
                try (var input = loader.getResourceAsStream(name + ".class")) {
                    if (input == null) {
                        return null;
                    }
                    var node = new ClassNode();
                    new ClassReader(input).accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                    return node;
                } catch (java.io.IOException unreadable) {
                    throw new java.io.UncheckedIOException(unreadable);
                }
            });
        }

        /** Whether an exception type is checked; a type whose class file is not found is treated as not. */
        boolean checked(String exception) {
            for (String current = exception; current != null; ) {
                switch (current) {
                    case "java/lang/RuntimeException", "java/lang/Error" -> {
                        return false;
                    }
                    case "java/lang/Exception", "java/lang/Throwable" -> {
                        return true;
                    }
                    default -> {
                        ClassNode node = type(current);
                        current = node == null ? null : node.superName;
                    }
                }
            }
            return false;
        }

        /** The first checked exception the method a call resolves to declares, searching its owner's
         * superclasses and interfaces, or null. */
        String checkedException(String owner, String name, String descriptor) {
            var pending = new java.util.ArrayDeque<String>(List.of(owner));
            while (!pending.isEmpty()) {
                ClassNode node = type(pending.poll());
                if (node == null) {
                    continue;
                }
                for (MethodNode declared : node.methods) {
                    if (declared.name.equals(name) && declared.desc.equals(descriptor)) {
                        return declared.exceptions.stream().filter(this::checked).findFirst().orElse(null);
                    }
                }
                if (node.superName != null) {
                    pending.add(node.superName);
                }
                pending.addAll(node.interfaces);
            }
            return null;
        }
    }

    /** Places the points of one method. */
    private final class MethodPlacer {
        final String owner;
        final MethodNode method;
        final Declarations declarations;
        final Target target;
        final Map<String, Integer> ordinals = new HashMap<>();
        final InsnList instructions;

        MethodPlacer(String owner, MethodNode method, Declarations declarations, Target target) {
            this.owner = owner;
            this.method = method;
            this.declarations = declarations;
            this.target = target;
            this.instructions = method.instructions;
        }

        int line(AbstractInsnNode instruction) {
            for (AbstractInsnNode current = instruction; current != null; current = current.getPrevious()) {
                if (current instanceof org.objectweb.asm.tree.LineNumberNode number) {
                    return number.line;
                }
            }
            return 0;
        }

        String place(String kind, AbstractInsnNode at, String anchor, boolean hashed) {
            String locator = target.prefix() + owner + ":" + method.name;
            String base = locator + "#" + digest(method.desc + " " + anchor);
            if (hashed) {
                int ordinal = ordinals.merge(base, 1, Integer::sum) - 1;
                locator = ordinal == 0 ? base : base + "." + ordinal;
            } else {
                locator = base;
            }
            String id = RuleSet.pointId(service, kind, locator);
            String code = (method.name + method.desc + " " + anchor).substring(0,
                    Math.min(CODE_WIDTH, (method.name + method.desc + " " + anchor).length()));
            points.add(new PointEntry(id, kind, target.prefix() + owner, line(at), method.name, code));
            return id;
        }

        void place() {
            if (placesPoints) {
                var calls = target.allows("call") ? throwingCalls() : Map.<MethodInsnNode, String>of();
                var loops = target.allows("loop") ? loopHeaders() : Map.<LabelNode, List<JumpInsnNode>>of();
                var branches = target.allows("branch") ? guardedThrows() : Map.<JumpInsnNode, String>of();
                var returns = switches.check() && target.allows("check") ? computedReturns() : List.<AbstractInsnNode>of();
                if (!returns.isEmpty()) {
                    String id = place("check", returns.get(0), "check", false);
                    for (AbstractInsnNode returned : returns) {
                        instructions.insertBefore(returned, call(id, "check", "(ZLjava/lang/String;)Z"));
                    }
                }
                for (Map.Entry<LabelNode, List<JumpInsnNode>> loop : loops.entrySet()) {
                    String id = place("loop", loop.getKey(), "loop", true);
                    for (JumpInsnNode backward : loop.getValue()) {
                        instructions.insertBefore(backward, call(id, "loop", "(Ljava/lang/String;)V"));
                    }
                }
                for (Map.Entry<JumpInsnNode, String> guarded : branches.entrySet()) {
                    forceable(guarded.getKey(), place("branch", guarded.getKey(), "throw " + guarded.getValue(), true));
                }
                for (Map.Entry<MethodInsnNode, String> throwing : calls.entrySet()) {
                    MethodInsnNode invoked = throwing.getKey();
                    observable(invoked, throwing.getValue(),
                            place("call", invoked, "call " + invoked.owner + "." + invoked.name + invoked.desc, true));
                }
            }
            for (AbstractInsnNode instruction : instructions.toArray()) {
                if (instruction instanceof MethodInsnNode invoked) {
                    // Boundary call sites belong to business code; in a library the boundary advice already sees them.
                    if (target.business()) {
                        replaceCallSite(invoked);
                    }
                    if (placesPoints && target.allows("clock")) {
                        wrapClockRead(invoked);
                    }
                }
            }
        }

        InsnList call(String id, String name, String descriptor) {
            var list = new InsnList();
            list.add(new LdcInsnNode(id));
            list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, POINTS, name, descriptor, false));
            return list;
        }

        /** Each loop, by the label its backward jumps return to, with those jumps; an iteration that
         * completes ends in one of them, so the point counts iterations rather than condition tests. */
        Map<LabelNode, List<JumpInsnNode>> loopHeaders() {
            var loops = new java.util.LinkedHashMap<LabelNode, List<JumpInsnNode>>();
            if (!switches.loop()) {
                return loops;
            }
            for (AbstractInsnNode instruction : instructions.toArray()) {
                if (instruction instanceof JumpInsnNode jump
                        && instructions.indexOf(jump.label) < instructions.indexOf(jump)) {
                    loops.computeIfAbsent(jump.label, ignored -> new ArrayList<>()).add(jump);
                }
            }
            return loops;
        }

        /** Conditional jumps that skip a straight-line block ending in athrow, with the thrown type. */
        Map<JumpInsnNode, String> guardedThrows() {
            var guarded = new java.util.LinkedHashMap<JumpInsnNode, String>();
            if (!switches.branch()) {
                return guarded;
            }
            for (AbstractInsnNode instruction : instructions.toArray()) {
                if (instruction.getOpcode() != Opcodes.ATHROW) {
                    continue;
                }
                String thrown = "?";
                for (AbstractInsnNode current = instruction.getPrevious(); current != null; current = current.getPrevious()) {
                    if (current instanceof TypeInsnNode created && created.getOpcode() == Opcodes.NEW) {
                        thrown = created.desc;
                    }
                    if (conditional(current)) {
                        JumpInsnNode jump = (JumpInsnNode) current;
                        if (instructions.indexOf(jump.label) > instructions.indexOf(instruction)) {
                            guarded.put(jump, thrown);
                        }
                        break;
                    }
                    if (transfers(current)) {
                        break;
                    }
                }
            }
            return guarded;
        }

        /** The ireturn instructions of a boolean method, unless every one returns a constant. */
        List<AbstractInsnNode> computedReturns() {
            var returns = new ArrayList<AbstractInsnNode>();
            if (!method.desc.endsWith(")Z")) {
                return returns;
            }
            boolean computed = false;
            for (AbstractInsnNode instruction : instructions.toArray()) {
                if (instruction.getOpcode() == Opcodes.IRETURN) {
                    returns.add(instruction);
                    int previous = instruction.getPrevious() == null ? -1 : instruction.getPrevious().getOpcode();
                    computed |= previous != Opcodes.ICONST_0 && previous != Opcodes.ICONST_1;
                }
            }
            return computed ? returns : List.of();
        }

        /** The calls whose callee declares a checked exception, with that exception; constructors are left
         * alone, since their receiver is not initialised while the call runs. */
        Map<MethodInsnNode, String> throwingCalls() {
            var calls = new java.util.LinkedHashMap<MethodInsnNode, String>();
            if (!switches.call() || method.name.equals("<init>")) {
                return calls;
            }
            for (AbstractInsnNode instruction : instructions.toArray()) {
                if (instruction instanceof MethodInsnNode invoked && !invoked.name.equals("<init>")
                        && !invoked.owner.startsWith("faultpoint/")) {
                    String exception = declarations.checkedException(invoked.owner, invoked.name, invoked.desc);
                    if (exception != null) {
                        calls.put(invoked, exception);
                    }
                }
            }
            return calls;
        }

        /** Surround a call with its point: Points.call before it may throw the declared exception in place of the
         * call, and the call's own return or throw is observed. A throw continues unchanged; after a return,
         * Points.returned, outside the handler, may throw the declared exception as if the callee had. */
        void observable(MethodInsnNode invoked, String exception, String id) {
            var start = new LabelNode();
            var end = new LabelNode();
            var handler = new LabelNode();
            var after = new LabelNode();
            var before = new InsnList();
            before.add(new LdcInsnNode(id));
            before.add(new LdcInsnNode(org.objectweb.asm.Type.getObjectType(exception)));
            before.add(new MethodInsnNode(Opcodes.INVOKESTATIC, POINTS, "call", "(Ljava/lang/String;Ljava/lang/Class;)V", false));
            before.add(start);
            instructions.insertBefore(invoked, before);
            var following = new InsnList();
            following.add(end);
            following.add(call(id, "returned", "(Ljava/lang/String;)V"));
            following.add(new JumpInsnNode(Opcodes.GOTO, after));
            following.add(handler);
            following.add(new InsnNode(Opcodes.DUP));
            following.add(call(id, "raised", "(Ljava/lang/Throwable;Ljava/lang/String;)V"));
            following.add(new InsnNode(Opcodes.ATHROW));
            following.add(after);
            instructions.insert(invoked, following);
            method.tryCatchBlocks.add(0, new org.objectweb.asm.tree.TryCatchBlockNode(start, end, handler, "java/lang/Throwable"));
        }

        /** Turn `if (condition) throw` into `if (Points.branch(condition, id)) throw`. */
        void forceable(JumpInsnNode jump, String id) {
            var skipped = new LabelNode();
            var done = new LabelNode();
            var list = new InsnList();
            list.add(new JumpInsnNode(jump.getOpcode(), skipped));
            list.add(new InsnNode(Opcodes.ICONST_1));
            list.add(new JumpInsnNode(Opcodes.GOTO, done));
            list.add(skipped);
            list.add(new InsnNode(Opcodes.ICONST_0));
            list.add(done);
            list.add(call(id, "branch", "(ZLjava/lang/String;)Z"));
            list.add(new JumpInsnNode(Opcodes.IFEQ, jump.label));
            instructions.insertBefore(jump, list);
            instructions.remove(jump);
        }

        void wrapClockRead(MethodInsnNode invoked) {
            String simpleOwner = invoked.owner.substring(invoked.owner.lastIndexOf('/') + 1);
            if (invoked.getOpcode() != Opcodes.INVOKESTATIC || !switches.clock().contains(simpleOwner + "." + invoked.name)) {
                return;
            }
            String returned = invoked.desc.substring(invoked.desc.indexOf(')') + 1);
            if (!returned.equals("J") && !returned.equals("Ljava/time/Instant;")) {
                return;
            }
            String id = place("clock", invoked, invoked.owner + "." + invoked.name, true);
            instructions.insert(invoked, call(id, "clock", "(" + returned + "Ljava/lang/String;)" + returned));
        }

        void replaceCallSite(MethodInsnNode invoked) {
            for (CallSite site : callSites.getOrDefault(invoked.owner, List.of())) {
                if (site.name().equals(invoked.name) && site.descriptor().equals(invoked.desc)) {
                    invoked.setOpcode(Opcodes.INVOKESTATIC);
                    invoked.owner = site.helperOwner();
                    invoked.name = site.helperName();
                    invoked.desc = site.helperDescriptor();
                    invoked.itf = false;
                    return;
                }
            }
        }
    }
}
