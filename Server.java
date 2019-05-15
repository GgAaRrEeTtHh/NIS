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
                s = ss.accept();
                System.out.println("Client connected");	
                
                while(s.isConnected()){
                
                  BufferedInputStream bs = new BufferedInputStream(s.getInputStream());
                  byte[] byteArray = new byte[1024];
                  int byt = bs.read(byteArray);
                  
                  ///COMMUMICATE/// 
                  System.out.println(" ******************************************************************* ");
                  
                  byteArray = decryptAndUnzip ( byteArray, byt );
                  
                  System.out.println("\n ****Decrypting Zip...\n\n  " +  (new String(byteArray , "UTF-8")) );
                  /////////////////
                  
                  //check if message hash and match
                  int keyLen = getKeyLen( byteArray );
                  String hash = new String (decryptRSA ( GenerateRSAKeys.readKeyFromFile("PubkeyClient.txt"), (Arrays.copyOfRange(byteArray,0, keyLen))));
                  String message = new String (Arrays.copyOfRange(byteArray,keyLen+1 ,byteArray.length ) );
                  message = message.substring(message.indexOf("+/")+2);
                  
                  ///COMMUMICATE///
                  System.out.println("\n\n ****message from client  \n>>"+ message ) ;
                  /////////////////
                  
                  if ( hash.equals(new String(sha1(message))) ){
                     System.out.println(" \n\n****Decrypted Message hash and Hash are EQUAL  ");
                     System.out.println(new String(sha1(message)) +" and " + hash);

                  }
                  else {
                     System.out.println(" \n\n****Decrypted Message hash and Hash are NOT EQUAL  ");
                     System.out.println(new String(sha1(message)) +" and " + hash);
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
            byte [] byteArrayKey =  Arrays.copyOfRange(byteArray,0, 256);                                                //extract key from recieved data
            System.out.println("\n ****Encrypted key Data : \n>>" + Base64.getEncoder().encodeToString(byteArrayKey) );
            byteArrayKey = decryptRSA ( privateKey , byteArrayKey) ;                                                     //decrypt key with RSA
            SecretKey secretKey = new SecretKeySpec(byteArrayKey, 0, byteArrayKey.length, "AES");                        //generate key from the data
            System.out.println(" \n****Key generated : \n>>" + Base64.getEncoder().encodeToString(secretKey.getEncoded()) );
            
            //use Ks to decrypt the message
            byte [] byteArrayData = Arrays.copyOfRange(byteArray, 256,len);                                              //extract message
            System.out.println(" \n****Encrypted Zipped Message from client:  \n\n>>" + Base64.getEncoder().encodeToString(byteArrayData) );
             
            //decrypt message with AES 
            this.cipher = Cipher.getInstance("AES");
            this.cipher.init(Cipher.DECRYPT_MODE, secretKey);
   		   byte[] decryptedBytes = cipher.doFinal(byteArrayData);                                                     //decrypt with AES
                      
            //unziip
            return decryptedBytes;
    }
    
    /**
    *
    * This method reduces the message to a single hashed value for digital signature
    *
    **/
    static byte [] sha1(String input) throws NoSuchAlgorithmException 
    {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        return  mDigest.digest(input.getBytes());
    }
    
    /**
     * Method decrypt messages with the Key and specified algorithm
     * for RSA
     *
     * @param publicKey uses generated public key.
     * @param message
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     **/
     
    public byte [] decryptRSA (Key key, byte [] message ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

           this.cipher = Cipher.getInstance(ALGORITHM_RSA);
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
    
    /**
    *
    *Get the keylength from the byte [] messsage sent from client
    *
    **/
    
    public int getKeyLen(byte [] byteMes) {
      
      String messageAndHash = new String ( byteMes );
      messageAndHash = messageAndHash.substring(messageAndHash.indexOf("+sep")+5);
      
      return Integer.parseInt(messageAndHash.substring(0, messageAndHash.indexOf('+')));
      
    }
    
    
    
}

