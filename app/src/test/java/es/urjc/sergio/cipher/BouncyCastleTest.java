package es.urjc.sergio.cipher;

import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.assertNotNull;

public class BouncyCastleTest {

    @Test
    public void testBC() {
        assertNotNull(Security.getProvider("BC"));
    }

}