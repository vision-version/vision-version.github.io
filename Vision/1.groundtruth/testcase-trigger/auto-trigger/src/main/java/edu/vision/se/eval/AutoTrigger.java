package edu.vision.se.eval;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.io.file.FileReader;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.core.io.resource.ClassPathResource;
import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson2.JSON;
import edu.vision.se.model.MetaInfo;
import edu.vision.se.model.TestcaseUnit;
import edu.vision.se.runner.RunResult;
import edu.vision.se.runner.TestcaseRunner;
import lombok.extern.slf4j.Slf4j;
import org.junit.runner.notification.Failure;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.*;
import java.util.stream.Collectors;

import static edu.vision.se.runner.RunStatus.COMPILE_ERROR;

@Slf4j
public class AutoTrigger {

    private static final String VULNERABILITY_LIST_NAME = "VULNERABILITY_NAME_LIST";

    private static final String GROUNDTRUTH_DIR_PATH = "/Users/zhouzhuotong/ClientDefender/groundtruth";

    private final static String OUTPUT_DIR = System.getProperty("user.dir") + File.separator + "trigger-output";

    public static void main(String[] args) throws IOException, InterruptedException {
        InputStream inputStream = new ClassPathResource(VULNERABILITY_LIST_NAME).getStream();
        String content = IoUtil.read(inputStream, Charset.defaultCharset());
        List<String> vulnNameList = Arrays.stream(content.split("\n")).collect(Collectors.toList());

        for (String vulnName : vulnNameList) {
            log.info("============ begin " + vulnName);
            File outputFile = FileUtil.file(OUTPUT_DIR, vulnName + ".json");
            if (outputFile.exists()) {
                log.info(vulnName + " exist, skip......");
                continue;
            }
            File file = FileUtil.file(GROUNDTRUTH_DIR_PATH, vulnName);
            File metainfoFile = FileUtil.file(file.getAbsolutePath(), "metainfo.json");
            String s = new FileReader(metainfoFile).readString();
            MetaInfo metaInfo = JSON.parseObject(s, MetaInfo.class);
            List<String> completeVersionList = metaInfo.getCompleteVersionList();
            List<TestcaseUnit> testcaseUnitList = metaInfo.getTestcaseUnitList();
            Map<String, List<String>> result = new HashMap<>();

            for (String version : completeVersionList) {
                log.info("version: " + version);
                List<String> list = new ArrayList<>();
                for (TestcaseUnit testcaseUnit : testcaseUnitList) {
                    String testcaseClassName = testcaseUnit.getTestcaseClassName();
                    TestcaseRunner runner = new TestcaseRunner(file);
                    RunResult runResult = runner.runTestcaseWithVersion(testcaseClassName, version);
                    switch (runResult.getRunStatus()) {
                        case FAIL_TRIGGER:
                            list.add("");
                            break;
                        case COMPILE_ERROR:
                            list.add(COMPILE_ERROR.name());
                            break;
                        case SUCCESS_TRIGGER:
                            List<Failure> failures = runResult.getFailureList();
                            System.out.println(failures);
                            Failure failure = failures.get(0);
                            Throwable exception = failure.getException();
                            list.add(exception.getClass().getName());
                            break;
                    }
                }
                result.put(version, list);
            }

            String prettyStr = JSONUtil.toJsonPrettyStr(result);
            FileWriter writer = new FileWriter(outputFile);
            writer.write(prettyStr);
            log.info("============ " + vulnName + " complete!");
        }
    }
}
