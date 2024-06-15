package edu.vision.se.state;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class GlobalStateTable {

    private static final Map<String, StateNode> STATE_TABLE = new ConcurrentHashMap<>();

    public static void reset() {
        STATE_TABLE.clear();
    }

    public static void addStateNode(String signature, Class clazz, Object value) {
        StateNode stateNode = new StateNode(signature, clazz, value);
        STATE_TABLE.put(signature, stateNode);
    }

    public static Map<String, StateNode> getStateTable() {
        Map<String, StateNode> stateTable = new HashMap<>();
        synchronized (GlobalStateTable.class) {
            for (Map.Entry<String, StateNode> stateNode : STATE_TABLE.entrySet()) {
                stateTable.put(stateNode.getKey(), stateNode.getValue());
            }
        }
        return stateTable;
    }
}
