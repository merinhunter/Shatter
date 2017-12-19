package es.urjc.sergio.assembler;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;

public class Slicer {
    private File file;
    private int blockSize;
    private Header header;

    public Slicer(File f, int blockSize, String sessionID) throws Exception {
        this.file = f;
        this.blockSize = blockSize;
        this.header = new Header(getBlocksNumber(), getFileSize(), sessionID);
    }

    private long getFileSize() {
        return file.length();
    }

    private long getBlocksNumber() {
        long nBlocks = getFileSize() / blockSize;

        if (getFileSize() % blockSize != 0)
            nBlocks++;

        return nBlocks;
    }

    public ArrayList<Slice> slice() throws FileNotFoundException {
        ArrayList<Slice> slices = new ArrayList<>();
        long nBlocks = getBlocksNumber();
        FileInputStream input = new FileInputStream(file);

        try {
            for (int i = 0; i < nBlocks; i++) {
                Slice slice = new Slice(i, header);
                byte[] buf = new byte[blockSize];

                input.read(buf, 0, blockSize);

                slice.setData(buf);
                slices.add(slice);
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e);
            System.exit(-1);
        } finally {
            try {
                if (input != null)
                    input.close();
            } catch (IOException e) {
                System.err.println("IO Exception closing files:");
                e.printStackTrace();
            }
        }

        return slices;
    }
}