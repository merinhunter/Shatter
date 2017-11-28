package es.urjc.sergio.common;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;

import cipher.EncFile;
import cipher.EncKeyFile;

public class FileIO {
    public final static String homePath = System.getenv("HOME");
    public final static String appPath = homePath + "/Shatter/";
    public final static String sendPath = appPath + "send/";
    public final static String donePath = "done/";
    public final static String decomposedPath = "/tmp/";

    public final static String badFile = "bad.txt";
    public final static String errorsFile = "errors.txt";
    public final static String doneFile = "done.txt";
    public final static String listFile = "list.txt";

    /**
     * Creates a directory in the specified path and, if it already exists, deletes
     * it.
     */
    public static boolean makeDirectory(String dirPath) {
        File dir = new File(dirPath);

        if (dir.exists())
            dir.delete();

        return dir.mkdir();
    }

    /**
     * Writes an ArrayList of EncFile in a specific path.
     *
     * @throws IOException
     */
    public static void write(ArrayList<EncFile> files, String destPath) throws IOException {
        RandomString random = new RandomString();

        for (EncFile file : files) {
            FileOutputStream output;

            while (true) {
                String fileName = random.nextString();
                String filePath = destPath + fileName;
                File f = new File(filePath);

                file.setID(fileName.getBytes());

                if (!f.exists() && !f.isDirectory()) {
                    output = new FileOutputStream(f);
                    break;
                }
            }

            output.write(file.toBytes(), 0, file.toBytes().length);

            if (output != null)
                output.close();
        }
    }

    /**
     * Writes a KeyFile in a specific path.
     *
     * @throws IOException
     */
    public static void write(EncKeyFile encKeyFile, String destPath) throws IOException {
        RandomString random = new RandomString();
        FileOutputStream output;

        while (true) {
            String fileName = random.nextString();
            String filePath = destPath + fileName + ".key";
            File f = new File(filePath);

            if (!f.exists() && !f.isDirectory()) {
                output = new FileOutputStream(f);
                break;
            }
        }

        output.write(encKeyFile.toBytes(), 0, encKeyFile.toBytes().length);

        if (output != null)
            output.close();
    }

    /**
     * Read an ArrayList of EncFile from a specific path.
     *
     * @throws IOException
     */
    public static ArrayList<EncFile> readEncFiles(String originPath) throws IOException {
        ArrayList<EncFile> files = new ArrayList<>();

        File folder = new File(originPath);
        File[] listOfFiles = folder.listFiles();
        Path path = null;

        for (File file : listOfFiles) {
            if (file.isFile() && !file.getName().endsWith(".key")) {
                path = Paths.get(file.getAbsolutePath());

                byte[] data = Files.readAllBytes(path);

                files.add(EncFile.fromBytes(data));
            }
        }

        return files;
    }

    /**
     * Read a KeyFile from a specific path.
     *
     * @throws IOException
     */
    public static EncKeyFile readEncKeyFile(String originPath) {
        File folder = new File(originPath);
        File[] listOfFiles = folder.listFiles();
        Path path = null;

        for (File file : listOfFiles) {
            if (file.isFile() && file.getName().endsWith(".key")) {
                path = Paths.get(file.getAbsolutePath());
                break;
            }
        }

        byte[] data;
        try {
            data = Files.readAllBytes(path);
        } catch (IOException e) {
            System.err.println("Error reading EncKeyFile");
            return null;
        }

        return EncKeyFile.fromBytes(data);
    }

    public static void append(String filePath, String m) {
        File file = new File(filePath);
        Path path = Paths.get(filePath);

        try {
            file.createNewFile();

            Files.write(path, m.getBytes(), StandardOpenOption.APPEND);
            Files.write(path, "\n".getBytes(), StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Error writing " + filePath + ": " + e.getMessage());
            System.exit(-1);
        }
    }

}
