package edu.vision.se.util;

import cn.hutool.core.io.FileUtil;
import lombok.extern.slf4j.Slf4j;
import soot.SootMethod;
import soot.Type;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

@Slf4j
public class MethodUtil {

    public static String getMethodSignature(String className, String methodName, org.objectweb.asm.Type returnType, org.objectweb.asm.Type[] argTypes) {
        String sb = "<" +
                className +
                ": " +
                corp(returnType.getClassName()) +
                " " +
                methodName +
                "(" +
                Arrays.stream(argTypes)
                        .map(org.objectweb.asm.Type::getClassName)
                        .map(MethodUtil::corp)
                        .collect(Collectors.joining(",")) +
                ")" +
                ">";
        return sb;
    }

    // obtain soot method signature
    public static String getMethodSignature(Class clazz, Method method) {
        String sb = "<" +
                clazz.getName() +
                ": " +
                corp(method.getReturnType().getName()) +
                " " +
                method.getName() +
                "(" +
                Arrays.stream(method.getParameterTypes())
                        .map(Class::getName)
                        .map(MethodUtil::corp)
                        .collect(Collectors.joining(",")) +
                ")" +
                ">";
        return sb;
    }

    public static String getMethodSignature(Class clazz, Constructor constructor) {
        String sb = "<" +
                clazz.getName() +
                ": " +
                "void <init>" +
                "(" +
                Arrays.stream(constructor.getParameterTypes())
                        .map(Class::getName)
                        .map(MethodUtil::corp)
                        .collect(Collectors.joining(",")) +
                ")" +
                ">";
        return sb;
    }

    public static String getMethodSignature(SootMethod sootMethod) {
        return sootMethod.getSignature();
    }

    public static String getShortMethodSignatureName(SootMethod sootMethod) {
        List<Type> params = sootMethod.getParameterTypes();
        StringBuilder sb = new StringBuilder();
        if (params == null || params.size() == 0) {
            sb.append("()");
        } else {
            sb.append("(");
            for (Type t : params) {
                String name = getNameOfType(t.toString());
                sb.append(name);
                sb.append(",");
            }
            sb.deleteCharAt(sb.length() - 1);
            sb.append(")");
        }
        String name = sootMethod.getDeclaringClass().getName() + "." + sootMethod.getName() + sb;
        return name;
    }

    private static String getNameOfType(String s) {
        int index = s.lastIndexOf(".");
        String shortName = s.substring(index + 1);
        return shortName;
    }

    public static String getMethodName(Method method) {
        return method.getName();
    }

    public static String getMethodDescriptor(Method method) {
        return org.objectweb.asm.Type.getMethodDescriptor(method);
    }

    public static String getMethodName(SootMethod sootMethod) {
        return sootMethod.getName();
    }

    public static String getMethodName(Constructor constructor) {
        return "<init>";
    }

    public static String getMethodDescriptor(Constructor constructor) {
        return org.objectweb.asm.Type.getConstructorDescriptor(constructor);
    }

    public static boolean containSetFieldMethod(Class clazz, Field field) {
        String fieldName = field.getName();
        String setterName = "set" + fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
        Method method = null;
        try {
            method = clazz.getMethod(setterName, field.getType());
        } catch (NoSuchMethodException e) {
            // do nothing
        }
        return method != null;
    }

    private static String corp(String name) {
        if (name.charAt(0) == '[') {
            int j = 0;
            int cnt = 0;
            while (name.charAt(j) == '[') {
                j++;
                cnt++;
            }

            if (name.charAt(j) == 'L') j++;

            name = name.substring(j);

            if (name.charAt(name.length() - 1) == ';') {
                name = name.substring(0, name.length() - 1);
            }

            switch (name) {
                case "V":
                    name = "void";
                    break;
                case "Z":
                    name = "boolean";
                    break;
                case "B":
                    name = "byte";
                    break;
                case "C":
                    name = "char";
                    break;
                case "S":
                    name = "short";
                    break;
                case "I":
                    name = "int";
                    break;
                case "J":
                    name = "long";
                    break;
                case "F":
                    name = "float";
                    break;
                case "D":
                    name = "double";
                    break;
                default:
                    break;
            }

            StringBuilder sb = new StringBuilder(name);
            for (int i = 0; i < cnt; i++) sb.append("[]");
            name = sb.toString();
            return name;
        } else {
            return name;
        }
    }
}
