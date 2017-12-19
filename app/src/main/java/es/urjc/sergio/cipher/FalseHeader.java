package es.urjc.sergio.cipher;

public class FalseHeader {
    private byte[] ID;

    byte[] getID() {
        return ID;
    }

    void setID(byte[] id) {
        ID = id;
    }

    @Override
    public String toString() {
        return new String(this.ID);
    }
}
