package es.urjc.sergio.assembler;

import java.nio.ByteBuffer;

import es.urjc.sergio.common.RandomString;
import es.urjc.sergio.rsa.Signature;

public class Header {
    final static int HEADER_SIZE = (Integer.SIZE / 8) + (Long.SIZE / 8)
            + RandomString.DEFAULT_SIZE + (Long.SIZE / 8) + Signature.BYTES;
    private final static int ID_SIZE = RandomString.DEFAULT_SIZE;
    private int index;
    private long nBlocks;
    private byte[] sessionID;
    private long fileSize;
    private Signature signature;

    Header(long nBlocks, long fileSize, String sessionID) {
        this.nBlocks = nBlocks;
        this.sessionID = sessionID.getBytes();
        this.fileSize = fileSize;
    }

    Header(Header header) {
        this.nBlocks = header.nBlocks;
        this.sessionID = header.sessionID;
        this.fileSize = header.fileSize;
    }

    private Header() {
    }

    static Header fromBytes(ByteBuffer buffer) {
        Header header = new Header();
        byte[] sessionID = new byte[ID_SIZE];
        byte[] signature = new byte[Signature.BYTES];

        header.index = buffer.getInt();
        header.nBlocks = buffer.getLong();
        buffer.get(sessionID);
        header.sessionID = sessionID;
        header.fileSize = buffer.getLong();
        buffer.get(signature);
        header.signature = new Signature(signature);

        return header;
    }

    public int getIndex() {
        return this.index;
    }

    void setIndex(int index) {
        this.index = index;
    }

    long getnBlocks() {
        return nBlocks;
    }

    long getFileSize() {
        return fileSize;
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }

    byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE);

        buffer.putInt(index);
        buffer.putLong(nBlocks);
        buffer.put(sessionID, 0, ID_SIZE);
        buffer.putLong(fileSize);
        buffer.put(signature.getSignature(), 0, Signature.BYTES);

        return buffer.array();
    }

    @Override
    public String toString() {
        String s = "";

        return s + index + "|" + nBlocks + "|" + new String(sessionID) + "|" + fileSize + "|"
                + this.signature.toString();
    }
}