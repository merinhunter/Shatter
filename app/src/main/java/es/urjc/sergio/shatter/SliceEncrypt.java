package es.urjc.sergio.shatter;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;

import es.urjc.sergio.assembler.Slice;
import es.urjc.sergio.assembler.Slicer;
import es.urjc.sergio.cipher.EncFile;
import es.urjc.sergio.cipher.EncKeyFile;
import es.urjc.sergio.cipher.Encryptor;
import es.urjc.sergio.cipher.KeyFile;
import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;
import es.urjc.sergio.common.RandomString;
import es.urjc.sergio.rsa.Signer;

public class SliceEncrypt {

    public static void sliceEncrypt(String filePath, String alias, int blockSize) {
        File f = new File(filePath);
        if (f.exists() && !f.isDirectory()) {

            try {
                RandomString random = new RandomString();
                String sessionID = random.nextString();
                String sessionPath = ExternalStorage.getFilePath(FileIO.sendPath + sessionID + "/");

                if (sessionPath == null)
                    throw new Exception("ExternalStorage unavailable");

                FileIO.makeDirectory(sessionPath);

                FileIO.append(ExternalStorage.getFilePath(FileIO.listFile), "ID:" + sessionID + " Path:" + filePath + " Alias:" + alias);

                Slicer slicer = new Slicer(f, blockSize, sessionID);
                ArrayList<Slice> slices = slicer.slice();

                Signer signer = new Signer(alias);
                for (Slice slice : slices) {
                    signer.sign(slice);
                }

                Encryptor encryptor = new Encryptor();
                ArrayList<EncFile> files = encryptor.encrypt(slices);
                for (EncFile file : files)
                    signer.sign(file);

                KeyFile keyFile = new KeyFile(encryptor.getKeyEncoded());
                signer.sign(keyFile);

                EncKeyFile encKeyFile = new EncKeyFile(keyFile, alias);

                FileIO.write(encKeyFile, sessionPath);

                FileIO.write(files, sessionPath);
            } catch (FileNotFoundException e) {
                System.err.println("FileNotFoundException: " + e.getMessage());
                System.exit(-1);
            } catch (Exception e) {
                System.err.println("Exception: " + e.getMessage());
                System.exit(-1);
            }

        } else {
            System.err.println("Specified path is not a file");
            System.exit(-1);
        }

        System.out.println("FINISH!");
    }
}
