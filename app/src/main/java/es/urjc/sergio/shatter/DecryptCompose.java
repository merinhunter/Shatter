package es.urjc.sergio.shatter;

import org.spongycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import es.urjc.sergio.assembler.Composer;
import es.urjc.sergio.assembler.Slice;
import es.urjc.sergio.cipher.Decryptor;
import es.urjc.sergio.cipher.EncFile;
import es.urjc.sergio.cipher.EncKeyFile;
import es.urjc.sergio.cipher.KeyFile;
import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;
import es.urjc.sergio.rsa.RSALibrary;
import es.urjc.sergio.rsa.Signer;

public class DecryptCompose {

    public static void decryptCompose(String sessionID, String alias) {
        String sessionPath = ExternalStorage.getFilePath(FileIO.appPath + sessionID + '/');
        String tmpPath = sessionPath + FileIO.decomposedPath;
        String badFilePath = sessionPath + FileIO.badFile;
        String errorsFilePath = sessionPath + FileIO.errorsFile;

        ArrayList<String> errors = new ArrayList<>();
        ArrayList<String> bad = new ArrayList<>();

        File dir = new File(tmpPath);
        if (dir.exists() && dir.isDirectory()) {

            EncKeyFile encKeyFile = FileIO.readEncKeyFile(tmpPath);
            if (encKeyFile == null) {
                System.err.println("EncKeyFile is missing");
                FileIO.append(errorsFilePath, "EncKeyFile is missing");
                System.exit(-1);
            }

            KeyFile keyFile = null;
            try {
                keyFile = new KeyFile(encKeyFile);
            } catch (Exception e) {
                System.err.println("EncKeyFile is corrupted");
                FileIO.append(badFilePath, "EncKeyFile is corrupted");
                System.exit(-1);
            }

            Signer signer = new Signer(alias);
            if (!signer.verify(keyFile)) {
                System.err.println("KeyFile has invalid signature");
                bad.add("KeyFile has invalid signature");
            }

            ArrayList<EncFile> files = new ArrayList<>();
            try {
                files = FileIO.readEncFiles(tmpPath);
            } catch (IOException e) {
                System.err.println("Error reading EncFiles");
                errors.add("Error reading EncFiles");
            }

            Decryptor decryptor = new Decryptor(keyFile.getKey());

            ArrayList<Slice> slices = new ArrayList<>();
            for (EncFile file : files) {
                if (!signer.verify(file)) {
                    System.err.println("IV of EncFile " + new String(file.getID()) + " is corrupted");
                    bad.add("IV of EncFile " + new String(file.getID()) + " is corrupted");
                }

                Slice slice = decryptor.decrypt(file);

                if (slice == null) {
                    System.err.println("EncFile " + new String(file.getID()) + " is corrupted");
                    bad.add("EncFile " + new String(file.getID()) + " is corrupted");
                    continue;
                }

                if (!signer.verify(slice)) {
                    System.err.println("Slice " + slice.getHeader().getIndex() + " has invalid signature");
                    bad.add("Slice " + slice.getHeader().getIndex() + " has invalid signature");
                }

                slices.add(slice);
            }

            Composer composer = new Composer(sessionID);
            if (!slices.isEmpty())
                composer.compose(slices);

            ArrayList<String> errorsComposer;
            if (composer.hasErrors()) {
                errorsComposer = composer.getErrors();
                errors.addAll(errorsComposer);
            }

        } else {
            System.err.println("There is not a path for the specified session ID");
            System.exit(-1);
        }

        if (!errors.isEmpty()) {
            System.err.println("Errors have occurred during the process");
            for (String m : errors)
                FileIO.append(errorsFilePath, m);
        }

        if (!bad.isEmpty()) {
            System.err.println("Some files are corrupted or have not passed the necessary security measures");
            for (String m : bad)
                FileIO.append(badFilePath, m);
        }

        System.out.println("FINISH!");
    }

}