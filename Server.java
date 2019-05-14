import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.io.*;
import java.util.*;


public class Server {

    ServerSocket ss;
    Socket s;
    Key publicKey;
    Key privateKey;
    PrintWriter p;
    GenerateRSAKeys keygen;
    private static Cipher cipher = null;
    private final static String ALGORITHM_AES = "AES/CBC/PKCS5Padding";
    private final static String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";



    public Server () throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    
      this.CreateKeys();	// Create private and public keys
      System.out.println("Public-Private key pair created for server");
      System.out.println("Server Public key saved to file PubkeyServer.txt");
      
    }
    
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, Exception, InvalidKeySpecException {
        Server server = new Server();
        server.run();
    }

    public void run() throws NoSuchAlgorithmException, Exception,  InvalidKeySpecException{
        
        try{
            ss = new ServerSocket(4999);
            
                System.out.println("Waiting for client");
                s = ss.accept();	// Accept client connection
                System.out.println("Client connected");	
                
                while(s.isConnected()){
                
                  BufferedInputStream bs = new BufferedInputStream(s.getInputStream());
                  byte[] byteArray = new byte[1024];
                  int byt = bs.read(byteArray);
                
                  String messageAndHash = new String( decryptAndUnzip ( byteArray, byt ), "UTF8"); // this returns a byte [] from gareth
                  
                  System.out.println(" Decrypting Message and Hash...  " +  messageAndHash);
                  //check if message hash and match
                  String hash = decrypt ( GenerateRSAKeys.readKeyFromFile("PubkeyClient.txt"), messageAndHash.substring(messageAndHash.indexOf('+')+1).getBytes() , 0).toString();
                  String message = messageAndHash.substring(0, messageAndHash.indexOf('+'));
                  
                  if ( hash.equals(sha1(message))){
                     System.out.println(" Decrypted Message hash and Hash are EQUAL  ");
                     System.out.println(sha1(message) +" and " + hash);

                  }
                  else {
                     System.out.println(" Decrypted Message hash and Hash are NOT EQUAL  ");
                     System.out.println(sha1(message) +" and " + hash);
                  } 
             }      
                
        }
        catch(IOException e){
            e.printStackTrace();
        }
    }
    
    /**
    *
    * decrypt takes in a byte array with message structure [ key_session + messasge ] with key 
    * encrypted with the public key and message encrypted with session_key
    * Uses RSA with private key to decrypt the key and AES to decrypt the message
    *
    * @return byte [] decryptedBytes
    * 
    * @throws NoSuchAlgorithmException
    * @throws InvalidAlgorithmParameterException
    * @throws InvalidKeyException   
    **/
    public byte [] decryptAndUnzip (byte [] byteArray, int len) throws Exception{
      
            //deccrypt the Ks with public(pub) key
            byte [] byteArrayKey = Arrays.copyOfRange(byteArray, 0,32);                                                 //extract key from recieved data
            System.out.println("\n Key data: >>" + new String(byteArrayKey, "UTF8") );
            byteArrayKey = decrypt ( privateKey , byteArrayKey , 0 ) ;                                                   //decrypt key with RSA
            SecretKey secretKey = new SecretKeySpec(byteArrayKey, 0, byteArrayKey.length, "AES");                        //generate key from the data
            System.out.println(" Key generated : " + Base64.getEncoder().encodeToString(secretKey.getEncoded()) );
            
            //use Ks to decrypt the message
            byte [] byteArrayData = Arrays.copyOfRange(byteArray, 32,len); //extract message
            System.out.println(" Encrypted message:\n>> " + new String(byteArrayData, "UTF8") );
             
            //decrypt message with AES 
            byte[] decryptedBytes = decrypt ( secretKey , byteArrayKey , 1 ) ;                                            //decrypt with AES
          
            //unziip and print message
           
            System.out.println( " decrypted message is:\n >>" + new String(decryptedBytes, "UTF8") );
            return decryptedBytes;
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
     * Method decrypt messages with the Key and specified algorithm
     * 0 for RSA and 1 for AES.
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
     
    public byte [] decrypt (Key key, byte [] message , int n) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

        if (n==0)
        this.cipher = Cipher.getInstance(ALGORITHM_RSA);
        else
        this.cipher = Cipher.getInstance(ALGORITHM_AES);
        
        cipher.init(Cipher.DECRYPT_MODE, key);
        return  cipher.doFinal(message);
    }
    
    /** 
    * CreateKeys() create public and private key 
    * for the server, Keys are created and then saved onto the server (txt file _ pubkeyServer.txt )
    *
    **/
    public void CreateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	
      this.keygen = new GenerateRSAKeys(2);	
    	Key[] keyring = new Key[2];			                           // position 0 has public key, position 1 has private key
    	keyring = keygen.KeyPairGen(2048);
      
    	this.publicKey = keyring[0];
      this.privateKey = keyring[1];
      
      this.keygen.getKeySpec("PubkeyServer.txt",this.publicKey);    	// saves public key to a file called pubkey
    }
    
    
    
}

