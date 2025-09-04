package edu.vision.se.util;

import lombok.NonNull;
import org.apache.commons.lang3.SerializationUtils;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

public class ObjectUtil {

    public static Object copyObject(Object object) {
        if (object == null) {
            return null;
        }

        if (Object.class.equals(object.getClass())) return new Object();

        if (checkIsSerializable(object.getClass())) {
            Serializable s = (Serializable) object;
            return SerializationUtils.clone(s);
        } else {
            return object;
        }
    }

    private static boolean checkIsSerializable(@NonNull Class clazz) {
        Class<?> superclass = clazz.getSuperclass();
        List<Class<?>> superClassInterfaces = Arrays.asList(superclass.getInterfaces());
        Class[] interfaces = clazz.getInterfaces();
        for (Class<?> inter : interfaces) {
            if (!superClassInterfaces.contains(inter) && Serializable.class.equals(inter)) {
                return true;
            }
        }
        return false;
    }
    
}
