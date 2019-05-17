import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


import static org.junit.jupiter.api.Assertions.*;

class GenerateRSAKeysTest {

    private GenerateRSAKeys rsaKeys;
    private Key[] key;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        this.rsaKeys = new GenerateRSAKeys(2);
        this.key = rsaKeys.KeyPairGen(2048);
    }

    @Test
    void keyPairGen() throws NoSuchAlgorithmException {

        assertEquals(2 , rsaKeys.KeyPairGen(2048).length); //Checks if 2 keys were generated
        assertEquals("X.509", key[0].getFormat());
        assertEquals("PKCS#8", key[1].getFormat());
        assertEquals("RSA", key[0].getAlgorithm());
        assertEquals("RSA", key[1].getAlgorithm());
    }

    //Tests if file has been created or not.
    @Test
    void getKeySpec() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        rsaKeys.getKeySpec("MajorKey.txt", key[0]);
        File file = new File("MajorKey.txt");
        assertTrue(file.exists());
    }

    @Test
    void readKeyFromFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        rsaKeys.getKeySpec("MajorKey.txt", key[0]);
        assertEquals("RSA", rsaKeys.readKeyFromFile("MajorKey.txt").getAlgorithm());
        assertEquals("X.509", rsaKeys.readKeyFromFile("MajorKey.txt").getFormat());
    }


}