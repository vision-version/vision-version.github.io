package edu.vision.se.instrument.state;

import edu.vision.se.util.ObjectUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class GlobalStateTable {

    private static final Map<String, StateNode> STATE_TABLE = new ConcurrentHashMap<>();

    public synchronized static void reset() {
        STATE_TABLE.clear();
    }

    public static void addStateNode(String signature, byte value) {
        Byte wrapperValue = value;
        StateNode stateNode = new StateNode(signature, byte.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    public static void addStateNode(String signature, boolean value) {
        Boolean wrapperValue = value;
        StateNode stateNode = new StateNode(signature, boolean.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    public static void addStateNode(String signature, char value) {
        Character wrapperValue = value;
        StateNode stateNode = new StateNode(signature, char.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    public static void addStateNode(String signature, short value) {
        Short wrapperValue = value;
        StateNode stateNode = new StateNode(signature, short.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    public static void addStateNode(String signature, int value) {
        Integer wrapperValue = value;
        StateNode stateNode = new StateNode(signature, int.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    public static void addStateNode(String signature, float value) {
        Float wrapperValue = value;
        StateNode stateNode = new StateNode(signature, float.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    public static void addStateNode(String signature, double value) {
        Double wrapperValue = value;
        StateNode stateNode = new StateNode(signature, double.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    public static void addStateNode(String signature, long value) {
        Long wrapperValue = value;
        StateNode stateNode = new StateNode(signature, long.class, wrapperValue);
        STATE_TABLE.put(signature, stateNode);
    }

    // instrument the input value of method
    public static void addStateNode(String signature, Object value) {
        StateNode stateNode = null;
        if (value == null) {
            stateNode = new StateNode(signature, Void.class, null);
        } else {
            Class<?> clazz = value.getClass();
            Object newValue = getCopyValue(value);
            stateNode = new StateNode(signature, clazz, newValue);
        }
        STATE_TABLE.put(signature, stateNode);
    }

    // instrument the return value of method
    public static void addStateNode(Object value, String signature) {
        StateNode stateNode = null;
        if (value == null) {
            stateNode = new StateNode(signature, Void.class, null);
        } else {
            Class<?> clazz = value.getClass();
            Object newValue = getCopyValue(value);
            stateNode = new StateNode(signature, clazz, newValue);
        }
        STATE_TABLE.put(signature, stateNode);
    }

    private static Object getCopyValue(Object object) {
        Object newValue;
        try {
            newValue = ObjectUtil.copyObject(object);
        } catch (Throwable e) {
            newValue = object;
        }
        return newValue;
    }


    public synchronized static Map<String, StateNode> getStateTable() {
        Map<String, StateNode> stateTable = new HashMap<>();
        synchronized (GlobalStateTable.class) {
            for (Map.Entry<String, StateNode> stateNode : STATE_TABLE.entrySet()) {
                stateTable.put(stateNode.getKey(), stateNode.getValue());
            }
        }
        return stateTable;
    }
}
