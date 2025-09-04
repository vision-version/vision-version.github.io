package edu.vision.se.runner;

import edu.vision.se.instrument.state.StateNode;
import edu.vision.se.model.TestcaseUnit;
import lombok.extern.slf4j.Slf4j;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import java.util.List;
import java.util.Map;

@Slf4j
public class RunResult {

    private RunStatus runStatus;

    private Result result;

    private List<Failure> failureList;

    private Map<String, StateNode> runStateTable;

    private TestcaseUnit testcaseUnit;

    public RunResult() {

    }

    public RunResult(RunStatus runStatus, Result result, Map<String, StateNode> runStateTable, TestcaseUnit testcaseUnit) {
        this.runStatus = runStatus;
        this.result = result;
        this.runStateTable = runStateTable;
        this.testcaseUnit = testcaseUnit;
    }

    public void setFailureList(List<Failure> failureList) {
        this.failureList = failureList;
    }

    public List<Failure> getFailureList() {
        return failureList;
    }

    public Result getResult() {
        return result;
    }

    public void setResult(Result result) {
        this.result = result;
    }

    public RunStatus getRunStatus() {
        return runStatus;
    }

    public void setRunStatus(RunStatus runStatus) {
        this.runStatus = runStatus;
    }

    public Map<String, StateNode> getRunStateTable() {
        return runStateTable;
    }

    public void setRunStateTable(Map<String, StateNode> runStateTable) {
        this.runStateTable = runStateTable;
    }

    public TestcaseUnit getTestcaseUnit() {
        return testcaseUnit;
    }

    public void setTestcaseUnit(TestcaseUnit testcaseUnit) {
        this.testcaseUnit = testcaseUnit;
    }

    @Override
    public String toString() {
        return "RunResult{" +
                "runStatus=" + runStatus +
                ", result=" + result +
                ", runStateTable=" + runStateTable +
                '}';
    }
}
