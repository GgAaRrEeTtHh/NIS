import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Authentication_Part2 {

    private final static String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";

    public Authentication_Part2() {}


    /**
     * Method decrypt messages with the public key.
     *
     * @param publicKey uses generated public key.
     * @param message
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String Decrypt_EP (PublicKey publicKey, String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

        Cipher cipher = Cipher.getInstance(ALGORITHM_RSA);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        // Decode string into bytes and decrypts
        byte[] decode = new BASE64Decoder().decodeBuffer(message);
        byte[] dec = cipher.doFinal(decode);

        return new String (dec, StandardCharsets.UTF_8);
    }

    // This method reduces the message to a single hashed value for digital signature
    static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }


    /**
     * Method compares the output of the hash function with the output of the received decrypted message.
     * @param OutputHash
     * @param OutputDecrypt
     * @return
     */
    public Boolean Compare (String OutputHash, String OutputDecrypt){
        if (OutputDecrypt.equalsIgnoreCase(OutputHash))
            return Boolean.TRUE;
        else
            return Boolean.FALSE;
    }

}
