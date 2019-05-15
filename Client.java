import java.net.*;
import java.nio.ByteBuffer;
import java.io.*;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

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
    PublicKey clientPubKey;    // clients public key
    PrivateKey clientPrivKey;  // clients private key
    

    public static void main(String[] args) throws Exception
    {
        try
        {
            Client client = new Client();
            client.run();

        }
        catch(NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }

    }
    public void run() throws Exception
    {
        try
        {
            Scanner scan = new Scanner(System.in);

            s = new Socket("localhost",5999);
            pr = new PrintWriter(s.getOutputStream());
          
            this.CreateKeys();   // creating public and private keys for client
            System.out.println("Public-Private key pair created for client");
            
            while(s.isConnected())
            { 	
	            System.out.println("Enter a message:");
	            String original = scan.nextLine();
	            String hashedMsg = sha1(original);         // hashing input from user
	            
	            System.out.println("Original + hashed");
	            System.out.println(original + " + " + hashedMsg);
	            
                System.out.println("Encrypting the hash...");
	            byte[] signedHash = this.rsaSigning(hashedMsg.getBytes()); // signing the hash
	           
	            System.out.println("Concatenating original message with encrypted hash (Separated by a \"+\")...");
	            String messageAndSignedHash = original+"+"+signedHash.toString(); // concatenating encrypted hash to the original message.
	            

                System.out.print("Original message and signed hash: ");
                System.out.println(messageAndSignedHash);
	            this.SaveToZip("ClientMessage.txt", messageAndSignedHash); // zipped client message


	            sessionKeyGenerator = new SessionKeyGenerator();
	            sessionKey = sessionKeyGenerator.getSessionKey();

	       
	            // encrypt zip file with session key
	            byte[] encryptedZip = sessionEncrypt("ZippedClientMessage.zip");
                
	           
	            // get public key of server
	            serverPubKey = GenerateRSAKeys.readKeyFromFile("PubkeyServer.txt");
	            
	            // wrap session key with public key of server
	            byte[] encryptedSession = wrapKey(serverPubKey, sessionKey);
	            System.out.println("Session key wrapped with public key of server");
	           
	            // send the byte arrays to the server
	            pr.println(encryptedZip.toString() +" :seperator: " +encryptedSession.toString());
	            
	            System.out.println("encrypted zip file and encrypted session key sent to server");
	            System.out.println(encryptedZip.toString() +" :seperator: " +encryptedSession.toString());
	            pr.flush();
            }
            s.close();
            scan.close();
        } 
        catch(IOException e)
        {
            e.printStackTrace();
        }
    }

    // This method reduces the message to a single hashed value for digital signature
    static String sha1(String input) throws NoSuchAlgorithmException 
    {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) 
        {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }
  
        return sb.toString();
    }

    public byte[] sessionEncrypt(String filename) throws Exception
    {
    		File inputFile = new File(filename);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
             
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
             
            byte[] outputBytes = cipher.doFinal(inputBytes);
             
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
        cipher.init(Cipher.WRAP_MODE, pubKey);
        final byte[] wrapped = cipher.wrap(symKey);
        return wrapped;
    }
    
    // used to save the final message as a zip file
    public void SaveToZip(String filename, String message) throws IOException 
    {
    	PrintWriter pr = new PrintWriter(filename);
    	pr.println(message);
    	pr.close();
    	
    	File f = new File("ZippedClientMessage.zip");
    	ZipOutputStream out =  new ZipOutputStream(new FileOutputStream(f));
    	ZipEntry e = new ZipEntry(filename);
    	out.putNextEntry(e);
    	
    	byte[] messageBytes = message.getBytes();
    	out.write(messageBytes, 0, messageBytes.length);
    	out.closeEntry();
    	out.close();
    }

     // Keys are created and then saved onto the client. Public key is made available to client and server
     public void CreateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException 
     {
    	this.clientside = new GenerateRSAKeys(2);	// creates a public and a private key
    	
    	Key[] keyring = new Key[2];			// position 0 has public key, position 1 has private key
    	keyring = clientside.KeyPairGen(2048);
    	this.clientPubKey = (PublicKey) keyring[0];
        this.clientside.getKeySpec("PubkeyClient.txt",this.clientPubKey);	// saves public key to a file called pubkey
    	this.clientPrivKey = (PrivateKey) keyring[1];
    }
}