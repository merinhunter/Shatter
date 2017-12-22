package es.urjc.sergio.common;

import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

import es.urjc.sergio.cipher.EncFile;
import es.urjc.sergio.cipher.EncKeyFile;

public class FileIO {
    public final static String appPath = "Shatter/";
    public final static String sendPath = appPath + "send/";
    public final static String certificatesPath = appPath + "certs/";
    public final static String donePath = "done/";
    public final static String decomposedPath = "tmp/";

    public final static String badFile = "bad.txt";
    public final static String errorsFile = "errors.txt";
    public final static String doneFile = "done.txt";
    public final static String listFile = appPath + "list.txt";

    /**
     * Creates a directory in the specified path and, if it already exists, deletes
     * it.
     */
    public static boolean makeDirectory(String dirPath) {
        File dir = new File(dirPath);

        if (dir.exists())
            dir.delete();

        return dir.mkdirs();
    }

    /**
     * Writes an ArrayList of EncFile in a specific path.
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
     */
    public static ArrayList<EncFile> readEncFiles(String originPath) throws IOException {
        ArrayList<EncFile> files = new ArrayList<>();

        File folder = new File(originPath);
        File[] listOfFiles = folder.listFiles();
        String path;

        for (File file : listOfFiles) {
            if (file.isFile() && !file.getName().endsWith(".key")) {
                path = file.getAbsolutePath();

                FileInputStream input = new FileInputStream(path);

                byte[] data = IOUtils.toByteArray(input);

                EncFile enc_file = EncFile.fromBytes(data);
                enc_file.setID(file.getName().getBytes());

                files.add(enc_file);
            }
        }

        return files;
    }

    /**
     * Read a KeyFile from a specific path.
     */
    public static EncKeyFile readEncKeyFile(String originPath) {
        File folder = new File(originPath);
        File[] listOfFiles = folder.listFiles();
        String path = null;

        for (File file : listOfFiles) {
            if (file.isFile() && file.getName().endsWith(".key")) {
                path = file.getAbsolutePath();
                break;
            }
        }

        FileInputStream input = null;
        try {
            input = new FileInputStream(path);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        byte[] data;
        try {
            data = IOUtils.toByteArray(input);
        } catch (IOException e) {
            System.err.println("Error reading EncKeyFile");
            return null;
        }

        return EncKeyFile.fromBytes(data);
    }

    public static void append(String filePath, String m) {
        File file = new File(filePath);

        try {
            file.createNewFile();

            FileWriter fw = new FileWriter(filePath, true);
            fw.write(m + "\n");
            fw.close();
        } catch (IOException e) {
            System.err.println("Error writing " + filePath + ": " + e.getMessage());
            System.exit(-1);
        }
    }

}
