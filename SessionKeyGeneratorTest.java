import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class SessionKeyGeneratorTest {

    private SessionKeyGenerator sessionKeyGenerator;

    @BeforeEach
    void setUp() throws Exception {
        this.sessionKeyGenerator = new SessionKeyGenerator();
    }


    @Test
    void getSessionKey() {
        assertEquals("AES", sessionKeyGenerator.getSessionKey().getAlgorithm()); //Test if algorithm is AES
        assertEquals(32, sessionKeyGenerator.getSessionKey().getEncoded().length); //Test if 32 length is returned
    }
}