package es.urjc.sergio.rsa;

import java.security.MessageDigest;
import org.spongycastle.pqc.math.linearalgebra.BigEndianConversions;

import es.urjc.sergio.common.Bytes;

public class MGF1 {
    private final MessageDigest digest;

    public MGF1(MessageDigest digest) {
        this.digest = digest;
    }

    public byte[] generateMask(byte[] mgfSeed, int maskLen) {
        int hashCount = (int) Math.ceil((float) maskLen / this.digest.getDigestLength());

        byte[] mask = new byte[0];

        for (int i = 0; i < hashCount; i++) {
            this.digest.update(mgfSeed);
            this.digest.update(BigEndianConversions.I2OSP(i, 4));
            byte[] hash = this.digest.digest();

            mask = Bytes.concat(mask, hash);
        }

        byte[] output = new byte[maskLen];
        System.arraycopy(mask, 0, output, 0, output.length);
        return output;
    }
}
