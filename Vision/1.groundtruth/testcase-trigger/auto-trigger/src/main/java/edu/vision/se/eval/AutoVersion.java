package edu.vision.se.eval;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.io.file.FileReader;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.core.io.resource.ClassPathResource;
import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.*;
import java.util.stream.Collectors;

public class AutoVersion {

    private static final String VERSION_OUTPUT_NAME = "vulnerable-version.json";
    private static final String VULNERABILITY_TYPE_NAME = "cve_testcase_type.json";

    private static final String VULNERABILITY_LIST_NAME = "VULNERABILITY_NAME_LIST";

    private final static String OUTPUT_DIR = System.getProperty("user.dir") + File.separator + "trigger-output";

    private static Map<String, List<String>> getVulnerabilityType() {
        InputStream inputStream = new ClassPathResource(VULNERABILITY_TYPE_NAME).getStream();
        String content = IoUtil.read(inputStream, Charset.defaultCharset());
        JSONObject jsonObject = JSON.parseObject(content);
        Map<String, List<String>> result = new HashMap<>();

        for (String cveName : jsonObject.keySet()) {
            List<String> list = jsonObject.getList(cveName, String.class);
            result.put(cveName, list);
        }
        return result;
    }

    public static List<String> getVulnerabilityList() {
        InputStream inputStream = new ClassPathResource(VULNERABILITY_LIST_NAME).getStream();
        String content = IoUtil.read(inputStream, Charset.defaultCharset());
        return Arrays.stream(content.split("\n")).collect(Collectors.toList());
    }

    public static void main(String[] args) {
        List<String> list = getVulnerabilityList();
        Map<String, List<String>> map = getVulnerabilityType();
//        map.forEach((key, value) -> System.out.println(key + ": " + value));

        Map<String, List<String>> versionMap = new HashMap<>();
        for (String cveName : list) {
            File file = FileUtil.file(OUTPUT_DIR, cveName + ".json");
            assert file.exists() && file.isFile() && map.containsKey(cveName);
            String s = new FileReader(file).readString();
            JSONObject jsonObject = JSON.parseObject(s);
            List<String> exceptedList = map.get(cveName);
            if (exceptedList == null) {
                System.out.println(cveName);
            }
            List<String> vulnerableVersionList = new ArrayList<>();
            for (String version : jsonObject.keySet()) {
                List<String> actualList = jsonObject.getList(version, String.class);
                if (exceptedList.equals(actualList)) {
                    vulnerableVersionList.add(version);
                }
            }
            Collections.sort(vulnerableVersionList);
            versionMap.put(cveName, vulnerableVersionList);
        }
        String prettyStr = JSONUtil.toJsonPrettyStr(versionMap);
        FileWriter writer = new FileWriter(FileUtil.file(System.getProperty("user.dir"), VERSION_OUTPUT_NAME));
        writer.write(prettyStr);
    }
}
