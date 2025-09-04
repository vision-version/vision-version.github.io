package edu.vision.se.eval;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.core.io.resource.ClassPathResource;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Map;

public class ProcessTriggerStatus {

    private final static String FILE_NAME = "TriggerStatus.json";

    private final static String TESTCASE_DIR = "";
    private final static String OUTPUT_DIR = System.getProperty("user.dir") + File.separator + "output";

    public static void main(String[] args) {
        InputStream inputStream = new ClassPathResource(FILE_NAME).getStream();
        String content = IoUtil.read(inputStream, Charset.defaultCharset());
        JSONObject jsonObject = JSONUtil.parseObj(content);

        for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
            String key = entry.getKey();
            JSONObject value = (JSONObject) entry.getValue();

            String cveName = FilenameUtils.getBaseName(key);
            String fileName = cveName + ".json";
            File file = FileUtil.file(OUTPUT_DIR, fileName);
            FileWriter writer = new FileWriter(file);
            writer.write(value.toStringPretty());
        }

    }
}
