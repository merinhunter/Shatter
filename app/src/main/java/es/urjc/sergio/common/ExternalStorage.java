package es.urjc.sergio.common;

import android.os.Environment;

import java.io.File;

public class ExternalStorage {

    /* Checks if external storage is available for read and write */
    private static boolean isExternalStorageWritable() {
        String state = Environment.getExternalStorageState();
        return Environment.MEDIA_MOUNTED.equals(state);
    }

    public static File getFile(String filePath) {
        if (isExternalStorageWritable()) {
            return new File(Environment.getExternalStorageDirectory().getAbsolutePath() +
                    File.separator + filePath);
        }

        return null;
    }

    public static String getFilePath(String filePath) {
        if (isExternalStorageWritable()) {
            return Environment.getExternalStorageDirectory().getAbsolutePath() +
                    File.separator + filePath;
        }

        return null;
    }

    public static boolean createDirs(String dirPath) {
        if (isExternalStorageWritable()) {
            File dir = new File(getFilePath(dirPath));
            return dir.mkdirs();
        }

        return false;
    }

}
