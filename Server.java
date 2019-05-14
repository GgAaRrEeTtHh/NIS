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
    GenerateRSAKeys keygen;	//object to create and save RSA keys
    private static Cipher cipher = null;


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
                
                  byte [] messageFromGareth = decryptAndUnzip ( byteArray, byt ); // this returns a byte [] from gareth
                   
                   
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
    **/
    public byte [] decryptAndUnzip(byte [] byteArray, int len) throws Exception{
      
            //deccrypt the Ks with public(pub) key
            byte [] byteArrayKey = Arrays.copyOfRange(byteArray, 0,32); //extract key from recieved data
            System.out.println("Key data: >>" + new String(byteArrayKey, "UTF8") );
            
            //decrypt with private key
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey); 
            SecretKey secretKey = new SecretKeySpec(byteArrayKey, 0, byteArrayKey.length, "AES");
            System.out.println("Key generated : " + Base64.getEncoder().encodeToString(secretKey.getEncoded()) );
            
            //use Ks to decrypt the message
            byte [] byteArrayData = Arrays.copyOfRange(byteArray, 32,len); //extract message
            System.out.println("Encrypted message: " + new String(byteArrayData, "UTF8") );
             
            //decrypt message with AES 
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
      		byte[] decryptedBytes = cipher.doFinal(byteArrayData);
          
           //unziip and print message
            System.out.println( "decrypted message is >>" + new String(decryptedBytes, "UTF8") );
            
            return decryptedBytes;
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

