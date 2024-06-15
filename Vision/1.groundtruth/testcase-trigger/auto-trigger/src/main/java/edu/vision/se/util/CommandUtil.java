package edu.vision.se.util;

import lombok.extern.slf4j.Slf4j;

import java.io.*;

@Slf4j
public class CommandUtil {

    public static int execCommand(String command) throws IOException, InterruptedException {
        String[] commandArr = command.split(" ");
        Process process = Runtime.getRuntime().exec(commandArr);

        InputStream inputStream = process.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;

        // output the process detail
        while ((line = reader.readLine()) != null) {
            log.info("exec command line output: {}", line);
        }
        return process.waitFor();
    }

    public static int execCommand(File file, String command) throws IOException, InterruptedException {
        return execCommand(file, command, true);
    }

    public static int execCommand(File file, String command, boolean logging) throws IOException, InterruptedException {
        String[] commandArr = command.split(" ");
        Process process = Runtime.getRuntime().exec(commandArr, null, file);

        InputStream inputStream = process.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;

        // output the process detail
        while ((line = reader.readLine()) != null) {
            if (logging) {
                log.info("exec command line output: {}", line);
            }
        }
        return process.waitFor();
    }

}
