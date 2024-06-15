package edu.vision.se.instrument;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import static org.objectweb.asm.Opcodes.ACC_ABSTRACT;
import static org.objectweb.asm.Opcodes.ACC_NATIVE;

public class SnoopTestcaseClassAdapter extends ClassVisitor {

    private final String className;

    private final String internalName;

    public SnoopTestcaseClassAdapter(int api, ClassVisitor classVisitor, String className, String internalName) {
        super(api, classVisitor);
        this.className = className;
        this.internalName = internalName;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (mv != null) {
            boolean isAbstractMethod = (access & ACC_ABSTRACT) != 0;
            boolean isNativeMethod = (access & ACC_NATIVE) != 0;
            if (!isAbstractMethod && !isNativeMethod) {
                mv = new SnoopTestcaseMethodAdapter(api, mv, className, access, name, descriptor);
            }
        }
        return mv;
    }

    @Override
    public void visitEnd() {
        super.visitEnd();
    }

    public String getClassName() {
        return className;
    }

    public String getInternalName() {
        return internalName;
    }

}
