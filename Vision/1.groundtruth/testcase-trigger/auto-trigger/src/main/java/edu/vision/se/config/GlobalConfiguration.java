package edu.vision.se.config;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileNameUtil;

import java.io.File;
import java.util.*;

public class GlobalConfiguration {

    public static final String MAVEN_HTML_FILE_NAME = "maven-page.html";

    public static final String METAINFO_FILE_NAME = "metainfo.json";

    public static final File WORK_DIR_FILE = FileUtil.file(FileUtil.getParent(System.getProperty("user.dir"), 1), "testcase-trigger");

    public static final Set<String> BAN_DIR_NAME = new HashSet<>(Arrays.asList("target", ".idea", ".DS_Store", ".vscode"));

    public static final String MAVEN_EXEC_COMMAND = System.getProperty("os.name").toLowerCase().contains("windows") ?
            "C:/Users/98082/tools/maven/bin/mvn.cmd clean package -DskipTests" : "mvn clean package -DskipTests";

    public static final String INSTRUMENT_DIR_PATH = System.getProperty("user.dir") + File.separator + ".instrument";

    public static final File INSTRUMENT_DIR_FILE = FileUtil.file(INSTRUMENT_DIR_PATH);

    public static List<File> getCVEDirFiles() {
        if (WORK_DIR_FILE.exists() && WORK_DIR_FILE.isDirectory()) {
            File[] files = WORK_DIR_FILE.listFiles(File::isDirectory);

            if (files == null) {
                throw new RuntimeException("the files array is null");
            }

            List<File> fileList = new ArrayList<>();
            for (File file : files) {
                String fileName = FileNameUtil.mainName(file);
                if (BAN_DIR_NAME.contains(fileName)) {
                    continue;
                }
                fileList.add(file);
            }

            return fileList;
        } else {
            throw new RuntimeException("the work directory is not exist.");
        }
    }

}
