package es.urjc.sergio.assembler;

import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;

public class SHA512CheckSumTest {

    @Test
    public void testChecksum1() {
        byte[] input = "abc".getBytes();
        byte[] hash = {(byte) 0xDD, (byte) 0xAF, (byte) 0x35, (byte) 0xA1, (byte) 0x93, (byte) 0x61, (byte) 0x7A,
                (byte) 0xBA, (byte) 0xCC, (byte) 0x41, (byte) 0x73, (byte) 0x49, (byte) 0xAE, (byte) 0x20, (byte) 0x41,
                (byte) 0x31, (byte) 0x12, (byte) 0xE6, (byte) 0xFA, (byte) 0x4E, (byte) 0x89, (byte) 0xA9, (byte) 0x7E,
                (byte) 0xA2, (byte) 0x0A, (byte) 0x9E, (byte) 0xEE, (byte) 0xE6, (byte) 0x4B, (byte) 0x55, (byte) 0xD3,
                (byte) 0x9A, (byte) 0x21, (byte) 0x92, (byte) 0x99, (byte) 0x2A, (byte) 0x27, (byte) 0x4F, (byte) 0xC1,
                (byte) 0xA8, (byte) 0x36, (byte) 0xBA, (byte) 0x3C, (byte) 0x23, (byte) 0xA3, (byte) 0xFE, (byte) 0xEB,
                (byte) 0xBD, (byte) 0x45, (byte) 0x4D, (byte) 0x44, (byte) 0x23, (byte) 0x64, (byte) 0x3C, (byte) 0xE8,
                (byte) 0x0E, (byte) 0x2A, (byte) 0x9A, (byte) 0xC9, (byte) 0x4F, (byte) 0xA5, (byte) 0x4C, (byte) 0xA4,
                (byte) 0x9F};

        try {
            assertEquals(Hex.toHexString(SHA512CheckSum.checksum(input)), Hex.toHexString(hash));
        } catch (Exception e) {
            System.err.println("Exception testChecksum1: " + e.getMessage());
            System.exit(-1);
        }
    }

    @Test
    public void testChecksum2() {
        byte[] input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                .getBytes();
        byte[] hash = {(byte) 0x8E, (byte) 0x95, (byte) 0x9B, (byte) 0x75, (byte) 0xDA, (byte) 0xE3, (byte) 0x13,
                (byte) 0xDA, (byte) 0x8C, (byte) 0xF4, (byte) 0xF7, (byte) 0x28, (byte) 0x14, (byte) 0xFC, (byte) 0x14,
                (byte) 0x3F, (byte) 0x8F, (byte) 0x77, (byte) 0x79, (byte) 0xC6, (byte) 0xEB, (byte) 0x9F, (byte) 0x7F,
                (byte) 0xA1, (byte) 0x72, (byte) 0x99, (byte) 0xAE, (byte) 0xAD, (byte) 0xB6, (byte) 0x88, (byte) 0x90,
                (byte) 0x18, (byte) 0x50, (byte) 0x1D, (byte) 0x28, (byte) 0x9E, (byte) 0x49, (byte) 0x00, (byte) 0xF7,
                (byte) 0xE4, (byte) 0x33, (byte) 0x1B, (byte) 0x99, (byte) 0xDE, (byte) 0xC4, (byte) 0xB5, (byte) 0x43,
                (byte) 0x3A, (byte) 0xC7, (byte) 0xD3, (byte) 0x29, (byte) 0xEE, (byte) 0xB6, (byte) 0xDD, (byte) 0x26,
                (byte) 0x54, (byte) 0x5E, (byte) 0x96, (byte) 0xE5, (byte) 0x5B, (byte) 0x87, (byte) 0x4B, (byte) 0xE9,
                (byte) 0x09};

        try {
            assertEquals(Hex.toHexString(SHA512CheckSum.checksum(input)), Hex.toHexString(hash));
        } catch (Exception e) {
            System.err.println("Exception testChecksum1: " + e.getMessage());
            System.exit(-1);
        }
    }

}