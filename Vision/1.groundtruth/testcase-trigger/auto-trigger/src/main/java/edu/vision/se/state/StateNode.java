package edu.vision.se.state;

public class StateNode {

    private String signature;

    private Class clazz;

    private Object value;

    public StateNode() {

    }

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

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public void setClazz(Class clazz) {
        this.clazz = clazz;
    }

}
