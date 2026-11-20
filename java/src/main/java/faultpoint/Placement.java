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

    private final String service;
    private final List<String> packages;
    private final Settings.Placement switches;
    private final Map<String, List<CallSite>> callSites = new HashMap<>();
    private final List<PointEntry> points = new ArrayList<>();
    private boolean placesPoints;

    public Placement(String service, List<String> packages, Settings.Placement switches) {
        this.service = service;
        this.packages = packages.stream().map(name -> name.replace('.', '/')).toList();
        this.switches = switches;
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

    boolean covers(String internalName) {
        return internalName != null && packages.stream().anyMatch(internalName::startsWith);
    }

    @Override
    public byte[] transform(ClassLoader loader, String internalName, Class<?> redefined, ProtectionDomain domain,
                            byte[] classfile) {
        if (!covers(internalName)) {
            return null;
        }
        try {
            return rewrite(classfile, loader);
        } catch (RuntimeException failure) {
            System.err.println("faultpoint: cannot rewrite " + internalName + ": " + failure);
            return null;
        }
    }

    byte[] rewrite(byte[] classfile, ClassLoader loader) {
        var node = new ClassNode();
        new ClassReader(classfile).accept(node, ClassReader.SKIP_FRAMES);
        for (MethodNode method : node.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE)) == 0) {
                new MethodPlacer(node.name, method).place();
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

    /** Places the points of one method. */
    private final class MethodPlacer {
        final String owner;
        final MethodNode method;
        final Map<String, Integer> ordinals = new HashMap<>();
        final InsnList instructions;

        MethodPlacer(String owner, MethodNode method) {
            this.owner = owner;
            this.method = method;
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
            String locator = owner + ":" + method.name;
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
            points.add(new PointEntry(id, kind, owner, line(at), method.name, code));
            return id;
        }

        void place() {
            if (placesPoints) {
                var loops = loopHeaders();
                var branches = guardedThrows();
                var returns = switches.check() ? computedReturns() : List.<AbstractInsnNode>of();
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
            }
            for (AbstractInsnNode instruction : instructions.toArray()) {
                if (instruction instanceof MethodInsnNode invoked) {
                    replaceCallSite(invoked);
                    if (placesPoints) {
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
