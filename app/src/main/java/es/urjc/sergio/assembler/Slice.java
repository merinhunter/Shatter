package es.urjc.sergio.assembler;

import java.nio.ByteBuffer;

public class Slice {
    private Header header;
    private byte[] data;

    Slice(int index, Header header) {
        this.header = new Header(header);
        this.header.setIndex(index);
    }

    private Slice(Header header) {
        this.header = header;
    }

    public static Slice fromBytes(byte[] byteArray) {
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        byte[] data = new byte[byteArray.length - Header.HEADER_SIZE];

        Header header = Header.fromBytes(buffer);
        Slice slice = new Slice(header);
        buffer.get(data);
        slice.setData(data);

        return slice;
    }

    public Header getHeader() {
        return header;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    private boolean isLastSlice() {
        return header.getIndex() == header.getnBlocks() - 1;

    }

    int getOriginalSize() {
        if (header.getFileSize() % data.length != 0)
            if (isLastSlice())
                return (int) header.getFileSize() % data.length;

        return data.length;
    }

    public byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(Header.HEADER_SIZE + data.length);

        buffer.put(header.toBytes(), 0, Header.HEADER_SIZE);
        buffer.put(data, 0, data.length);

        return buffer.array();
    }

    @Override
    public String toString() {
        return header.toString() + "|" + new String(data);
    }
}