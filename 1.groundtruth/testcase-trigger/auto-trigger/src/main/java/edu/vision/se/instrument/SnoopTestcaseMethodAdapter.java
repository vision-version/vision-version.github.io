package edu.vision.se.instrument;

import edu.vision.se.util.MethodUtil;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.GeneratorAdapter;

public class SnoopTestcaseMethodAdapter extends GeneratorAdapter implements Opcodes {

    private final String className;

    private final Integer methodAccess;

    private final String methodName;

    private final String methodDescriptor;

    private final String methodSignature;

    public SnoopTestcaseMethodAdapter(int api, MethodVisitor methodVisitor, String className, int access, String name, String descriptor) {
        super(api, methodVisitor, access, name, descriptor);
        this.methodSignature = MethodUtil.getMethodSignature(className, name, getReturnType(), getArgumentTypes());
        this.className = className;
        this.methodAccess = access;
        this.methodName = name;
        this.methodDescriptor = descriptor;
    }

    @Override
    public void visitCode() {
        this.onMethodEnter();
        super.visitCode();
    }

    @Override
    public void visitInsn(int opcode) {
        if ((opcode >= IRETURN && opcode <= RETURN) || opcode == ATHROW) {
            this.onMethodExit(opcode);
        }
        super.visitInsn(opcode);
    }

    protected void onMethodEnter() {
        if (mv != null) {
            boolean isStaticOrConstructor = ((methodAccess & ACC_STATIC) != 0) || "<init>".equals(methodName);
            int slotIndex = isStaticOrConstructor ? 0 : 1;

            Type[] argumentTypes = super.getArgumentTypes();
            for (int i = slotIndex; i < argumentTypes.length; i++) {
                String key = this.methodSignature + "#" + (i - (isStaticOrConstructor ? 0 : 1));
                mv.visitLdcInsn(key);
                Type t = argumentTypes[i];
                super.loadArg(i);
                super.box(t);
                mv.visitMethodInsn(INVOKESTATIC, TestcaseClassLoader.STATE_TABLE_INTERNAL_NAME, TestcaseClassLoader.ADD_STATE_NODE_METHOD_NAME, "(Ljava/lang/String;Ljava/lang/Object;)V", false);
            }

            if (!isStaticOrConstructor) {
                String key = this.methodSignature + "#this";
                mv.visitLdcInsn(key);
                super.loadThis();
                mv.visitMethodInsn(INVOKESTATIC, TestcaseClassLoader.STATE_TABLE_INTERNAL_NAME, TestcaseClassLoader.ADD_STATE_NODE_METHOD_NAME, "(Ljava/lang/String;Ljava/lang/Object;)V", false);
            }
        }
    }

    protected void onMethodExit(int opcode) {
        if (mv != null) {
            if (opcode == ATHROW || opcode == RETURN || "<init>".equals(methodName)) {
                return;
            }

            // instrument the return value
            if (opcode == ARETURN) {
                dup();
                storageReturnValue();
            } else if (opcode == LRETURN || opcode == DRETURN) {
                dup2();
                storageReturnValue();
            } else {
                dup();
                storageReturnValue();
            }
        }
    }

    private void storageReturnValue() {
        box(getReturnType());
        String key = this.methodSignature + "#return";
        mv.visitLdcInsn(key);
        mv.visitMethodInsn(INVOKESTATIC, TestcaseClassLoader.STATE_TABLE_INTERNAL_NAME, TestcaseClassLoader.ADD_STATE_NODE_METHOD_NAME, "(Ljava/lang/Object;Ljava/lang/String;)V", false);
    }

    public Integer getMethodAccess() {
        return methodAccess;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getMethodDescriptor() {
        return methodDescriptor;
    }

    public String getClassName() {
        return className;
    }

    public String getMethodSignature() {
        return methodSignature;
    }

}
