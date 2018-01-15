package es.urjc.sergio.assembler;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;

public class Composer {
    private String donePath, filePath, doneFilePath;
    private ArrayList<String> errors;
    private FileOutputStream output;

    public Composer(String sessionID) {
        String sessionPath = ExternalStorage.getFilePath(FileIO.appPath + sessionID + '/');
        this.donePath = sessionPath + FileIO.donePath;
        this.filePath = donePath + sessionID;
        this.doneFilePath = sessionPath + FileIO.doneFile;

        this.errors = new ArrayList<>();
    }

    public boolean hasErrors() {
        return !this.errors.isEmpty();
    }

    public ArrayList<String> getErrors() {
        return errors;
    }

    private boolean writeSlice(Slice slice, int expected) throws IOException {
        System.out.println("Writing slice " + slice.getHeader().getIndex());

        if (slice.getHeader().getIndex() != expected) {
            System.err.println("Slice " + expected + " is missing");
            errors.add("Slice " + expected + " is missing");

            output.write(new byte[slice.getOriginalSize()], 0, slice.getOriginalSize());

            return false;
        }

        if (output != null)
            output.write(slice.getData(), 0, slice.getOriginalSize());

        System.out.println("Slice " + slice.getHeader().getIndex() + " written");
        FileIO.append(doneFilePath, "Slice " + slice.getHeader().getIndex() + " written");

        return true;
    }

    public void compose(ArrayList<Slice> slices) {

        if (!FileIO.makeDirectory(donePath)) {
            System.err.println("Error creating " + donePath);
            errors.add("Error creating " + donePath);
            return;
        }

        File file = new File(filePath);

        if (file.exists() || file.isDirectory()) {
            System.err.println("File already exists");
            errors.add("File already exists");
            return;
        }

        try {
            this.output = new FileOutputStream(file);
        } catch (FileNotFoundException e1) {
            System.err.println("File " + file.getAbsolutePath() + " not found");
            errors.add("File " + file.getAbsolutePath() + " not found");
        }

        Collections.sort(slices, new Comparator<Slice>() {
            @Override
            public int compare(Slice s1, Slice s2) {
                return s1.getHeader().getIndex() - s2.getHeader().getIndex();
            }
        });

        long nBlocks = slices.get(0).getHeader().getnBlocks();

        int i = 0;

        for (Slice slice : slices) {
            try {
                while (!writeSlice(slice, i))
                    i++;
            } catch (IOException e) {
                System.err.println("Error reading slice " + slice.getHeader().getIndex());
                errors.add("Error reading slice " + slice.getHeader().getIndex());
            }

            i++;
        }

        if (i != nBlocks) {
            System.err.println("Slice " + i + " missing");
            errors.add("Slice " + i + " is missing");
        }

        if (output != null)
            try {
                output.close();
            } catch (IOException e) {
                System.err.println("Error closing the stream");
            }
    }
}