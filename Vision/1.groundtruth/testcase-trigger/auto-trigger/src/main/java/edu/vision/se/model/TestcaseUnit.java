package edu.vision.se.model;

import com.alibaba.fastjson2.annotation.JSONField;

import java.util.List;
import java.util.Objects;

public class TestcaseUnit {
    @JSONField(deserialize = false, serialize = false)
    private String groupId;

    @JSONField(deserialize = false, serialize = false)
    private String artifactId;

    @JSONField(name = "vulMethodSignature")
    private String vulMethodSignature;

    @JSONField(name = "methodName")
    private String testcaseMethodName;

    @JSONField(name = "className")
    private String testcaseClassName;

    @JSONField(name = "exceptedThrowable")
    private String exceptedThrowableName;

    @JSONField(name = "needValidateReturnValue")
    private boolean needValidateReturnValue;

    @JSONField(name = "validateReturnValueMethodName")
    private String validateReturnValueMethodName;

    @JSONField(name = "needValidateThrow")
    private boolean needValidateThrow;

    @JSONField(name = "validateThrowMethodName")
    private String validateThrowMethodName;

    public TestcaseUnit() {

    }

    public TestcaseUnit(String vulMethodSignature, String testcaseMethodName, String testcaseClassName) {
        this.vulMethodSignature = vulMethodSignature;
        this.testcaseMethodName = testcaseMethodName;
        this.testcaseClassName = testcaseClassName;
    }

    public String getExceptedThrowableName() {
        return exceptedThrowableName;
    }

    public boolean isNeedValidateReturnValue() {
        return needValidateReturnValue;
    }

    public boolean isNeedValidateThrow() {
        return needValidateThrow;
    }

    public void setExceptedThrowableName(String exceptedThrowableName) {
        this.exceptedThrowableName = exceptedThrowableName;
    }

    public String getValidateReturnValueMethodName() {
        return validateReturnValueMethodName;
    }

    public void setNeedValidateReturnValue(boolean needValidateReturnValue) {
        this.needValidateReturnValue = needValidateReturnValue;
    }

    public void setNeedValidateThrow(boolean needValidateThrow) {
        this.needValidateThrow = needValidateThrow;
    }

    public void setValidateReturnValueMethodName(String validateReturnValueMethodName) {
        this.validateReturnValueMethodName = validateReturnValueMethodName;
    }

    public void setValidateThrowMethodName(String validateThrowMethodName) {
        this.validateThrowMethodName = validateThrowMethodName;
    }

    public String getValidateThrowMethodName() {
        return validateThrowMethodName;
    }

    public void setArtifactId(String artifactId) {
        this.artifactId = artifactId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getTestcaseClassName() {
        return testcaseClassName;
    }

    public String getTestcaseMethodName() {
        return testcaseMethodName;
    }

    public String getVulMethodSignature() {
        return vulMethodSignature;
    }

    public void setTestcaseClassName(String testcaseClassName) {
        this.testcaseClassName = testcaseClassName;
    }

    public void setTestcaseMethodName(String testcaseMethodName) {
        this.testcaseMethodName = testcaseMethodName;
    }

    public void setVulMethodSignature(String vulMethodSignature) {
        this.vulMethodSignature = vulMethodSignature;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TestcaseUnit that = (TestcaseUnit) o;

        if (!Objects.equals(vulMethodSignature, that.vulMethodSignature))
            return false;
        if (!Objects.equals(testcaseMethodName, that.testcaseMethodName))
            return false;
        return Objects.equals(testcaseClassName, that.testcaseClassName);
    }

    @Override
    public int hashCode() {
        int result = vulMethodSignature != null ? vulMethodSignature.hashCode() : 0;
        result = 31 * result + (testcaseMethodName != null ? testcaseMethodName.hashCode() : 0);
        result = 31 * result + (testcaseClassName != null ? testcaseClassName.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "TestcaseUnit{" +
                "vulMethodSignature='" + vulMethodSignature + '\'' +
                ", testcaseMethodName='" + testcaseMethodName + '\'' +
                ", testcaseClassName='" + testcaseClassName + '\'' +
                '}';
    }
}
