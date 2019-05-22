import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class ServerTest {

    private Server server;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.server = new Server();
    }

    //Test to see if the output returned is correct
    @Test
    void sha1() throws NoSuchAlgorithmException {
        assertEquals(20, Server.sha1("abc").length);
    }


    //Tests if file has been created.
    @Test
    void createKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.server.CreateKeys();
        File file = new File("PubkeyServer.txt");
        assertTrue(file.exists());

        String content = new String(Files.readAllBytes(Paths.get("PubkeyServer.txt")));
        assertTrue(content.isEmpty() == false);
    }
}