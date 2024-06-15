package edu.vision.se.runner;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileReader;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson2.JSON;
import edu.vision.se.config.GlobalConfiguration;
import edu.vision.se.instrument.TestcaseClassLoader;
import edu.vision.se.instrument.state.GlobalStateTable;
import edu.vision.se.instrument.state.StateNode;
import edu.vision.se.model.MetaInfo;
import edu.vision.se.model.TestcaseUnit;
import edu.vision.se.parser.POMParser;
import edu.vision.se.util.CommandUtil;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class TestcaseRunner {
    private static final String METAINFO_FILE_NAME = "metainfo.json";

    private static final String POM_FILE_NAME = "pom.xml";

    private static List<String> cveManualList = new ArrayList<>();

    public static final String DEPENDENCY_DIR_NAME = "dependency";

    private final String testcaseDirPath;

    private final File testcaseDir;

    private POMParser pomParser;

    private MetaInfo metaInfo;

    private File targetDir;

    private File classesDir;

    private File dependencyDir;

    public TestcaseRunner(@NonNull String testcaseDirPath) {
        if (Files.notExists(Paths.get(testcaseDirPath))) {
            testcaseDirPath = testcaseDirPath.replace("",
                    "");
        }
        this.testcaseDir = FileUtil.file(testcaseDirPath);
        if (this.testcaseDir.isDirectory()) {
            // do nothing
        } else {
            throw new RuntimeException("the input is not directory");
        }
        this.testcaseDirPath = testcaseDir.getAbsolutePath();
        readDataFromMetaInfo();
        createPOMParser();
  
        cveManualList.add("CVE-2022-26336");
        cveManualList.add("CVE-2023-34454");
    }

    public TestcaseRunner(@NonNull File testcaseDir) {
        this.testcaseDir = testcaseDir;
        if (this.testcaseDir.isDirectory()) {
            // do nothing
        } else {
            throw new RuntimeException("the input is not directory");
        }
        this.testcaseDirPath = this.testcaseDir.getAbsolutePath();
        readDataFromMetaInfo();
        createPOMParser();
    }

    private void createPOMParser() {
        File pomFile = FileUtil.file(testcaseDirPath, POM_FILE_NAME);
        this.pomParser = new POMParser(pomFile);
    }

    private void readDataFromMetaInfo() {
        File file = FileUtil.file(testcaseDirPath, METAINFO_FILE_NAME);
        if (file.isFile()) {
            FileReader reader = new FileReader(file);
            this.metaInfo = JSON.parseObject(reader.readString(), MetaInfo.class);
        } else {
            throw new RuntimeException("the metainfo file not exist.");
        }
    }

    private synchronized boolean compileTestcaseProject(String version) throws IOException, InterruptedException {
        // modify the library version
        pomParser.updatePOMFileVersion(metaInfo.getGroupId(), metaInfo.getArtifactId(), version);

        // compile testcase maven project
        this.targetDir = FileUtil.file(testcaseDir, "target");
        if (this.targetDir.exists()) {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                String command = "cmd /c rmdir /s /q " + targetDir.getAbsolutePath();
                Runtime.getRuntime().exec(command);
            } else {
                FileUtil.del(this.targetDir);
            }

        }
        this.classesDir = FileUtil.file(targetDir, "classes");
        this.dependencyDir = FileUtil.file(targetDir, DEPENDENCY_DIR_NAME);
        CommandUtil.execCommand(testcaseDir, GlobalConfiguration.MAVEN_EXEC_COMMAND, false);

        if (targetDir.exists() && targetDir.isDirectory()
                && classesDir.exists() && classesDir.isDirectory()
                && dependencyDir.exists() && dependencyDir.isDirectory()) {
            return true;
        } else {
            return false;
        }
    }

    private synchronized ClassLoader getTestcaseClassLoader() throws IOException {

        List<String> paths = Files.walk(Paths.get(dependencyDir.getAbsolutePath()))
                .map(Path::toString).collect(Collectors.toList());
        paths.add(classesDir.getAbsolutePath());

        // Create instrumenting testcase class loader
        return new TestcaseClassLoader(paths);
    }

    private TestcaseUnit findTestcaseUnit(@NonNull String className) {
        for (TestcaseUnit testcaseUnit : metaInfo.getTestcaseUnitList()) {
            if (className.equals(testcaseUnit.getTestcaseClassName())) {
                return testcaseUnit;
            }
        }
        return null;
    }

    public synchronized RunResult runTestcaseWithVersion(@NonNull String className, @NonNull String version)
            throws IOException, InterruptedException {
        RunResult runResult = new RunResult();
        TestcaseUnit testcaseUnit = findTestcaseUnit(className);

        if (testcaseUnit == null) {
            throw new RuntimeException("the className '" + className + "' not exist");
        }

        runResult.setTestcaseUnit(testcaseUnit);
        boolean compileSuccess = compileTestcaseProject(version);
        if (compileSuccess) {
            ClassLoader loader = getTestcaseClassLoader();

            // current state
            ClassLoader currentLoader = Thread.currentThread().getContextClassLoader();
            String currentUserDir = System.getProperty("user.dir");
            GlobalStateTable.reset();

            // switch the context
            Thread.currentThread().setContextClassLoader(loader);
            System.setProperty("user.dir", testcaseDirPath);

            // run the junit testcase
            try {
                Class<?> clazz = loader.loadClass(className);

                Class<?> junitCoreClass = loader.loadClass("org.junit.runner.JUnitCore");

                Method runClassesMethod = junitCoreClass.getDeclaredMethod("runClasses", Class[].class);
                Object[] arguments = {new Class[]{clazz}};
                Result result = (Result) runClassesMethod.invoke(null, arguments);
                List<Failure> failures = result.getFailures();
                runResult.setFailureList(failures);
                runResult.setResult(result);
            } catch (Throwable t) {
                log.error("JUnitCoreRunError: ", t);
                runResult.setFailureList(null);
                runResult.setResult(null);
            }

            // set to the origin context
            Thread.currentThread().setContextClassLoader(currentLoader);
            System.setProperty("user.dir", currentUserDir);

            Map<String, StateNode> stateTable = GlobalStateTable.getStateTable();
            runResult.setRunStateTable(stateTable);

            // check the run status
            if (runResult.getFailureList() != null) {
                if (!runResult.getFailureList().isEmpty()) {
                    runResult.setRunStatus(RunStatus.SUCCESS_TRIGGER);
                } else {
                    runResult.setRunStatus(RunStatus.FAIL_TRIGGER);
                }
            } else {
                runResult.setRunStatus(RunStatus.COMPILE_ERROR);
            }
        } else {
            runResult.setRunStatus(RunStatus.COMPILE_ERROR);
        }
        return runResult;
    }

    public Map<String, RunResult> runTestcaseWithMultiVersion(String className, Collection<String> versionList)
            throws IOException, InterruptedException, ClassNotFoundException {
        Map<String, RunResult> resultMap = new HashMap<>();
        for (String version : versionList) {
            RunResult runResult = runTestcaseWithVersion(className, version);
            resultMap.put(version, runResult);
        }
        return resultMap;
    }

    public Map<String, RunResult> runTestcaseWithMultiVersion(String className, String[] versions)
            throws IOException, InterruptedException, ClassNotFoundException {
        Map<String, RunResult> resultMap = new HashMap<>();
        for (String version : versions) {
            RunResult runResult = runTestcaseWithVersion(className, version);
            resultMap.put(version, runResult);
        }
        return resultMap;
    }

    public File getTestcaseDir() {
        return testcaseDir;
    }

    public String getTestcaseDirPath() {
        return testcaseDirPath;
    }

    public MetaInfo getMetaInfo() {
        return metaInfo;
    }

    public POMParser getPomParser() {
        return pomParser;
    }

    public static void main(String[] args) throws IOException, InterruptedException, ClassNotFoundException {

        String currentPath = System.getProperty("user.dir");
        currentPath = FileUtil.getParent(currentPath, 2);

     
    
        File jsonFile = FileUtil.file(currentPath,
                "4-testcase-app/affected_version/GABV_Gen/triggerinfo_for_autotrigger.json");
        String jsonStr = FileUtil.readString(jsonFile, Charset.defaultCharset());


        JSONObject jsonObject = JSONUtil.parseObj(jsonStr);
   
        List<String> toTagLst = new ArrayList<>(jsonObject.keySet());


        File cacheTriggerFile = FileUtil.file(currentPath,
                "4-testcase-app/affected_version/GATriggeredV_Gen/TriggerStatus.json");
        String cacheTriggerCVEs = FileUtil.readString(cacheTriggerFile, Charset.defaultCharset());
        JSONObject triggerCVEs = JSONUtil.parseObj(cacheTriggerCVEs);

        List<String> taggedLst = new ArrayList<>(triggerCVEs.keySet());


        for (String runnerKey : toTagLst) {

            if (!runnerKey.contains("CVE-2022-22968")) continue;


            TestcaseRunner runner = new TestcaseRunner(runnerKey);
            if (cveManualList.stream().anyMatch(runnerKey::endsWith)) {
  
                continue;
            }
  
            JSONObject cveInfo = jsonObject.getJSONObject(runnerKey);
            JSONArray testcasesObj = cveInfo.getJSONArray("testcases");
            JSONArray versionsObj = cveInfo.getJSONArray("versions");
            // Convert to List
            List<String> testcases = testcasesObj.toList(String.class);
            List<String> versions = versionsObj.toList(String.class);

            Map<String, Map<String, List<String>>> version1Dictionary = new HashMap<>();
            // 5. Run test cases with values from JSON
            for (String version : versions) {
                // if (version.startsWith("23.0.")) continue;
                System.out.println(version);
                // if (!version.startsWith("42.2.13")) continue;
                Map<String, List<String>> version1TestCases = new HashMap<>();
                for (String testcase : testcases) {
                    version1TestCases.put(testcase, new ArrayList<>());
                    List<String> failurelstForTestcase = version1TestCases.get(testcase);
                    // 6. Create TestcaseRunner

                    RunResult runResult = runner.runTestcaseWithVersion(testcase, version);

                    if (runResult.getResult() != null) {
                        List<Failure> failures = runResult.getResult().getFailures();
                        for (Failure failure : failures) {
                            String exceptionAsString = failure.getException().toString();
                            failurelstForTestcase.add(exceptionAsString);
                        }
                    }
                }
                version1Dictionary.put(version, version1TestCases);
            }
            triggerCVEs.put(runnerKey, version1Dictionary);

            String jsonString = JSONUtil.toJsonStr(triggerCVEs);

            File file = FileUtil.file(currentPath,
                    "4-testcase-app/affected_version/GATriggeredV_Gen/TriggerStatus.json");
            FileUtil.writeUtf8String(jsonString, file.getAbsolutePath());
        }
    }
}