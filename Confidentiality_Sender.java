import sun.misc.BASE64Encoder;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;


public class Confidentiality_Sender {


    // Attributes
    private Cipher cipher;
    private final static String ALGORITHM_AES = "AES/CBC/PKCS5Padding";
    private final static String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";


    /**
     * Method generates the secret key using AES algorithm
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    /**
     * Method encrypts the message and secret key with the AES algorithm.
     *
     * @param text ziped plaintext message.
     * @param secretKey generated secret key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String EncryptAES (String  text, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        this.cipher = Cipher.getInstance(ALGORITHM_AES);

        byte[] bs = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bs);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(bs);

        this.cipher.init(Cipher.ENCRYPT_MODE,secretKey, ivParameterSpec);

        // Encode string into bytes using UTF-8
        byte[] encoded = text.getBytes(StandardCharsets.UTF_8);

        // Encrypt the encoded bytes
        byte[] encrypt = cipher.doFinal(encoded);

        // Return encoded base64 bytes to ouput a string
        return new BASE64Encoder().encode(encrypt);
    }

    /**
     * Method encrypts messages with the public key.
     *
     * @param publicKey generated public key.
     * @param message
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String encrypt_EP (PublicKey publicKey, String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(ALGORITHM_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encode string into bytes using UTF-8 and encrypt
        byte[] encode_utf8 = message.getBytes(StandardCharsets.UTF_8);
        byte[] enc = cipher.doFinal(encode_utf8);

        return new BASE64Encoder().encode(enc);
    }




}
