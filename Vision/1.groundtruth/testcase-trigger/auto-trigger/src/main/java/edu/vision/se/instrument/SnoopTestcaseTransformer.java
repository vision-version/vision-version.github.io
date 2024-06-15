package edu.vision.se.instrument;

import lombok.extern.slf4j.Slf4j;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

@Slf4j
public class SnoopTestcaseTransformer implements ClassFileTransformer {
    private final static String[] CLASS_BAN_LIST = {"edu/vision/se", "cn/hutool", "org/junit", "junit", "[", "java/lang", "org/eclipse/collections", "edu/berkeley/cs/jqf/fuzz/util", "janala", "org/objectweb/asm", "sun", "jdk", "java/util/function"};

    private boolean shouldExclude(String cname) {
        for (String e : CLASS_BAN_LIST) {
            if (cname.startsWith(e)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public byte[] transform(ClassLoader loader, String classInternalName, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (classInternalName == null) {
            return null;
        }
        String className = classInternalName.replace('/', '.');

        boolean toInstrument = !shouldExclude(classInternalName);

        if (toInstrument) {
            try {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new SnoopTestcaseClassWriter(cr, loader, ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                ClassVisitor cv = new SnoopTestcaseClassAdapter(Opcodes.ASM9, cw, className, classInternalName);
                cr.accept(cv, ClassReader.EXPAND_FRAMES | ClassReader.SKIP_DEBUG);
                return cw.toByteArray();
            } catch (Throwable t) {
                log.warn("SnoopTestcaseTransformer Warning Occur");
                return null;
            }
        } else {
            return classfileBuffer;
        }
    }
}