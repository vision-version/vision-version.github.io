package edu.vision.se.instrument;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;

public class SnoopTestcaseClassWriter extends ClassWriter {

    private final ClassLoader loader;


    public SnoopTestcaseClassWriter(ClassReader cr, ClassLoader loader, final int flags) {
        super(cr, flags);
        this.loader = loader != null ? loader : ClassLoader.getSystemClassLoader();
    }

    @Override
    protected String getCommonSuperClass(final String type1, final String type2) {
        try {
            ClassReader info1 = typeInfo(type1);
            ClassReader info2 = typeInfo(type2);
            if ((info1.getAccess() & Opcodes.ACC_INTERFACE) != 0) {
                if (typeImplements(type2, info2, type1)) {
                    return type1;
                } else {
                    return "java/lang/Object";
                }
            }
            if ((info2.getAccess() & Opcodes.ACC_INTERFACE) != 0) {
                if (typeImplements(type1, info1, type2)) {
                    return type2;
                } else {
                    return "java/lang/Object";
                }
            }
            StringBuilder b1 = typeAncestors(type1, info1);
            StringBuilder b2 = typeAncestors(type2, info2);
            String result = "java/lang/Object";
            int end1 = b1.length();
            int end2 = b2.length();
            while (true) {
                int start1 = b1.lastIndexOf(";", end1 - 1);
                int start2 = b2.lastIndexOf(";", end2 - 1);
                if (start1 != -1 && start2 != -1
                        && end1 - start1 == end2 - start2) {
                    String p1 = b1.substring(start1 + 1, end1);
                    String p2 = b2.substring(start2 + 1, end2);
                    if (p1.equals(p2)) {
                        result = p1;
                        end1 = start1;
                        end2 = start2;
                    } else {
                        return result;
                    }
                } else {
                    return result;
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e.toString());
        }
    }

    private StringBuilder typeAncestors(String type, ClassReader info)
            throws IOException {
        StringBuilder b = new StringBuilder();
        while (!"java/lang/Object".equals(type)) {
            b.append(';').append(type);
            type = info.getSuperName();
            info = typeInfo(type);
        }
        return b;
    }

    private boolean typeImplements(String type, ClassReader info, String itf)
            throws IOException {
        while (!"java/lang/Object".equals(type)) {
            String[] itfs = info.getInterfaces();
            for (int i = 0; i < itfs.length; ++i) {
                if (itfs[i].equals(itf)) {
                    return true;
                }
            }
            for (int i = 0; i < itfs.length; ++i) {
                if (typeImplements(itfs[i], typeInfo(itfs[i]), itf)) {
                    return true;
                }
            }
            type = info.getSuperName();
            info = typeInfo(type);
        }
        return false;
    }

    private ClassReader typeInfo(final String type) throws IOException {
        String resource = type + ".class";
        InputStream is = loader.getResourceAsStream(resource);
        if (is == null) {
            throw new IOException("Cannot create ClassReader for type " + type);
        }
        try {
            return new ClassReader(is);
        } finally {
            is.close();
        }
    }
}

