package edu.vision.se.parser;

import cn.hutool.core.io.FileUtil;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.model.io.xpp3.MavenXpp3Writer;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

@Slf4j
public class POMParser {
    private final String pomFilePath;

    private final File pomFile;

    public POMParser(@NonNull String pomFilePath) {
        this.pomFile = FileUtil.file(pomFilePath);
        if (this.pomFile.exists() && this.pomFile.isFile()) {
            // do nothing
        } else {
            throw new RuntimeException("input is not a file or file not exist.");
        }
        this.pomFilePath = this.pomFile.getAbsolutePath();
    }

    public POMParser(@NonNull File pomFile) {
        if (pomFile.exists() && pomFile.isFile()) {
            this.pomFile = pomFile;
            this.pomFilePath = pomFile.getAbsolutePath();
        } else {
            throw new RuntimeException("input is not a file or file not exist.");
        }
    }

    public boolean updatePOMFileVersion(@NonNull String targetGroupId, @NonNull String targetArtifactId, @NonNull String newVersion) {
        try {
            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(new FileReader(pomFile));

            // 获取所有的依赖项
            List<Dependency> dependencies = model.getDependencies();
            boolean foundDependency = false;

            // 遍历依赖项，检查是否存在匹配的 artifactId 和 groupId
            for (Dependency dependency : dependencies) {
                if (targetGroupId.equals(dependency.getGroupId()) && targetArtifactId.equals(dependency.getArtifactId())) {
                    dependency.setVersion(newVersion); // 更新版本
                    foundDependency = true;
                    break; // 可以选择立即退出循环，因为已经找到了匹配的依赖项
                }
            }

            if (!foundDependency) {
                log.warn("not found corresponding dependency.");
                return false;
            }

            // 将更新后的模型写回 pom.xml 文件
            MavenXpp3Writer writer = new MavenXpp3Writer();
            FileWriter fileWriter = new FileWriter(pomFile);
            writer.write(fileWriter, model);
            fileWriter.close();

            return true;
        } catch (IOException | XmlPullParserException e) {
            log.error("WritePOMFileError: ", e);
            return false;
        }
    }

    public File getPomFile() {
        return pomFile;
    }

    public String getPomFilePath() {
        return pomFilePath;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        POMParser pomParser = (POMParser) o;

        return Objects.equals(pomFilePath, pomParser.pomFilePath);
    }

    @Override
    public int hashCode() {
        int result = pomFilePath != null ? pomFilePath.hashCode() : 0;
        result = 31 * result + (pomFile != null ? pomFile.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "POMParser{" +
                ", pomFile=" + pomFile +
                '}';
    }

}