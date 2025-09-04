package edu.vision.se.instrument.state;

public class StateNode {

    private final String signature;

    private final Class clazz;

    private final Object value;

    public StateNode(String signature, Class clazz, Object value) {
        this.signature = signature;
        this.clazz = clazz;
        this.value = value;
    }

    public String getSignature() {
        return signature;
    }

    public Object getValue() {
        return value;
    }

    public Class getClazz() {
        return clazz;
    }



    @Override
    public String toString() {
        return "StateNode{" +
                "clazz=" + (clazz == null ? null : clazz.toString()) +
                ", value=" + (value == null ? value : value.toString()) +
                '}';
    }
}
