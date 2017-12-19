package es.urjc.sergio.common;

import java.math.BigInteger;

public class Bytes {

    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new InternalError("Byte a must equal Byte b");
        }

        byte[] output = new byte[a.length];

        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) (a[i] ^ b[i]);
        }

        return output;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] output = new byte[a.length + b.length];

        System.arraycopy(a, 0, output, 0, a.length);
        System.arraycopy(b, 0, output, a.length, b.length);
        return output;
    }

    public static byte[] concat(byte[] a, byte[] b, byte[] c) {
        return concat(a, concat(b, c));
    }

    public static byte[] I2OSP(BigInteger x, int xLen) {
        if (x.signum() != 1)
            throw new IllegalArgumentException("BigInteger not positive.");

        byte[] x_bytes = x.toByteArray();
        int x_len = x_bytes.length;

        if (x_len <= 0)
            throw new IllegalArgumentException("BigInteger too small.");

        int x_off = (x_bytes[0] == 0) ? 1 : 0;
        x_len -= x_off;

        if (x_len > xLen)
            throw new IllegalArgumentException("BigInteger too large.");

        byte[] res_bytes = new byte[xLen];
        int res_off = xLen - x_len;
        System.arraycopy(x_bytes, x_off, res_bytes, res_off, x_len);
        return res_bytes;
    }
}
