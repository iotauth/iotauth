package org.iot.auth.io;

import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Created by hokeunkim on 3/6/17.
 */
public class FileIOHelper {
    public static byte[] readFully(String filePath) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(filePath, "r");
        byte[] bytes = new byte[(int)randomAccessFile.length()];
        randomAccessFile.readFully(bytes);
        randomAccessFile.close();
        return bytes;
    }
    public static void writeFully(String filePath, byte[] bytes) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(filePath, "rws");
        randomAccessFile.write(bytes);
        randomAccessFile.close();
    }
}
