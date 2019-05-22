import java.net.*;
import java.nio.ByteBuffer;
import java.io.*;
import java.util.*;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.util.zip.Deflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

public class Client
{

    Socket s;
    PrintWriter pr;
    GenerateRSAKeys clientside;
    SessionKeyGenerator sessionKeyGenerator;
    SecretKey sessionKey;
    PublicKey serverPubKey;
    PublicKey clientPubKey;                                           // clients public key
    PrivateKey clientPrivKey;                                         // clients private key
    static boolean testMode = false;
    
    // Constructor used in junit testing
    public Client(boolean mode) throws Exception
    {
    	testMode = mode;
    	this.CreateKeys();   // creating public and private keys for client
        System.out.println("Public-Private key pair created for client");
        System.out.println("Testing Mode");
    }	
	
    // Constructor used for normal operations
    public Client() throws Exception {
    
      this.CreateKeys();   // creating public and private keys for client
      System.out.println("Public-Private key pair created for client");

    }

    public static void main(String[] args) throws Exception
    {
        try{
            Client client = new Client();
            client.run();
        }
        catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }

    }
    public void run() throws Exception
    {
        try{
        
            Scanner scan = new Scanner(System.in);
            s = new Socket("localhost",4999);
            OutputStream socketOutputStream = s.getOutputStream(); 
                                 
            while(s.isConnected())
            { 	
	            System.out.println("Enter a message:");
               byte [] original = (scan.nextLine()).getBytes();
               byte [] hashedMsg = sha1(new String(original));                                           // hashing input from user
               
               System.out.println("*************************************************");
               System.out.println("****Encrypting the hash...");                                             //COMUNICATiNG
	            hashedMsg = this.rsaSigning(hashedMsg);                                                   // signing the hash
               //original = ( "+sep+" +hashedMsg.length+" +/" + (new String(original) )).getBytes();
               
	            System.out.println("\n****Original + hashed: \n>>"  );
	            System.out.println( (new String(original)) + " + " + (new String(hashedMsg)) );
	            
               //zip the message and signed hash
	            byte [] messageAndSignedHash = compress ( addTwoArrays (hashedMsg, original) );                       // concatenating encrypted hash to the original message.
	            
              
	            sessionKeyGenerator = new SessionKeyGenerator();
	            sessionKey = sessionKeyGenerator.getSessionKey();
               System.out.println("\n****Session key in base64: \n>>" + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
               
	            // encrypt zip file with session key
	            byte [] encryptedZip = sessionEncrypt( messageAndSignedHash );
               System.out.println("\n****encrypted zip : \n\n>>" + Base64.getEncoder().encodeToString(encryptedZip) );
               
	            // wrap sesssion key with public key of server
	            serverPubKey = GenerateRSAKeys.readKeyFromFile("PubkeyServer.txt");
	            byte[] encryptedSession = wrapKey(serverPubKey, sessionKey);
               System.out.println("\n****Encrypted  key : \n\n>>" + Base64.getEncoder().encodeToString(encryptedSession));
               
	            // send the byte arrays to the server
               socketOutputStream.write(addTwoArrays (encryptedSession , encryptedZip ));

               socketOutputStream.flush();
	            
	            System.out.println("encrypted zip file and encrypted session key sent to server");
               System.out.println("******************************************\n");
            }
            s.close();
            scan.close();
        } 
        catch(IOException e)
        {
            e.printStackTrace();
        }
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
    *
    * This method adds two byte []  objects
    *
    **/
    public byte [] addTwoArrays( byte [] A, byte [] B ) {
    
         byte[] combined = new byte[A.length + B.length];
         System.arraycopy(A,0,combined,0         ,A.length);
         System.arraycopy(B,0,combined,A.length,B.length);
         
         return combined;
    }
    
    /**
    *
    * Encrypt zipped file with session key
    *
    **/
    public byte[] sessionEncrypt( byte [] testByte) throws Exception
    {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey); 
            byte[] outputBytes = cipher.doFinal(testByte);
            
    		return outputBytes;         
    }


    public byte[] rsaSigning(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clientPrivKey);
        byte[] cipherData = cipher.doFinal(data);
        return cipherData;      
    }

    public static byte[] wrapKey(PublicKey pubKey, SecretKey symKey) throws Exception
    {
        
    	   final Cipher cipher = Cipher.getInstance("RSA");//"RSA/ECB/OAEPWithSHA1AndMGF1Padding");
         cipher.init(Cipher.ENCRYPT_MODE, pubKey);
         final byte[] wrapped = cipher.doFinal(symKey.getEncoded());
         return wrapped;
    }

     /**
     *
     * Keys are created and then saved onto the client. Public key is made available to client and server
     *
     **/
     public void CreateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException 
     {
    	this.clientside = new GenerateRSAKeys(2);	                           // creates a public and a private key
    	
    	Key[] keyring = new Key[2];			                                 // position 0 has public key, position 1 has private key
    	keyring = clientside.KeyPairGen(2048);
    	this.clientPubKey = (PublicKey) keyring[0];
        this.clientside.getKeySpec("PubkeyClient.txt",this.clientPubKey);	// saves public key to a file called pubkey
    	this.clientPrivKey = (PrivateKey) keyring[1];
    }
    
    /**
    *
    * The method compress, takes in a by
    *
    *
    **/
    public byte [] compress ( byte [] bytes ) 
    {
       		 
		   Deflater deflater = new Deflater();
		   deflater.setInput(bytes);
		   deflater.finish();
		   ByteArrayOutputStream bos = new ByteArrayOutputStream(bytes.length);
		   
		   byte[] buffer = new byte[1024];
		   
		   while(!deflater.finished())
		   {		   		 
		   		 int bytesCompressed = deflater.deflate(buffer);
		   		 bos.write(buffer,0,bytesCompressed);
		   }
		   
		   try
		   {
			   //close the output stream
			   bos.close();
		   }
		   catch(IOException ioe)
		   {
		   		System.out.println(ioe);
		   }
		   
		   //get the compressed byte array from output stream
		   byte[] compressedArray = bos.toByteArray();
         
         return compressedArray;
		   
    }
}
