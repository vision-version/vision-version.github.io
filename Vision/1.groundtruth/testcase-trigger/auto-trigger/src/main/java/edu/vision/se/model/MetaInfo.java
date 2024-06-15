package edu.vision.se.model;

import com.alibaba.fastjson2.annotation.JSONField;

import java.io.File;
import java.util.List;

public class MetaInfo {

    @JSONField(name = "vulName")
    private String vulName;

    @JSONField(name = "groupId")
    private String groupId;

    @JSONField(name = "artifactId")
    private String artifactId;

    @JSONField(name = "affectedVersion")
    private List<String> affectedVersion;

    @JSONField(name = "complete_version")
    private List<String> completeVersionList;

    @JSONField(name = "testcases")
    private List<TestcaseUnit> testcaseUnitList;

    @JSONField(deserialize = false, serialize = false)
    private transient File storageDir;

    public MetaInfo() {

    }

    public MetaInfo(String groupId, String artifactId, List<String> completeVersionList, List<TestcaseUnit> testcaseUnitList) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.completeVersionList = completeVersionList;
        this.testcaseUnitList = testcaseUnitList;
    }

    public List<String> getAffectedVersion() {
        return affectedVersion;
    }

    public void setAffectedVersion(List<String> affectedVersion) {
        this.affectedVersion = affectedVersion;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public List<String> getCompleteVersionList() {
        return completeVersionList;
    }

    public File getStorageDir() {
        return storageDir;
    }

    public void setVulName(String vulName) {
        this.vulName = vulName;
    }

    public List<TestcaseUnit> getTestcaseUnitList() {
        return testcaseUnitList;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public void setArtifactId(String artifactId) {
        this.artifactId = artifactId;
    }

    public void setCompleteVersionList(List<String> completeVersionList) {
        this.completeVersionList = completeVersionList;
    }

    public void setStorageDir(File storageDir) {
        this.storageDir = storageDir;
    }

    public String getVulName() {
        return vulName;
    }

    public void setTestcaseUnitList(List<TestcaseUnit> testcaseUnitList) {
        this.testcaseUnitList = testcaseUnitList;
    }

    @Override
    public String toString() {
        return "MetaInfo{" +
                "groupId='" + groupId + '\'' +
                ", artifactId='" + artifactId + '\'' +
                ", completeVersionList=" + completeVersionList +
                ", testcaseUnitList=" + testcaseUnitList +
                ", storageDir=" + storageDir +
                '}';
    }
}

