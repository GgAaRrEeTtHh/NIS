package clientServer;

import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidKeyException;
import java.security.Key;
//import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

public class Client{

    Socket s;
    PrintWriter pr;
    GenerateRSAKeys clientside;
    PublicKey clientkey;    // clients public key
    PrivateKey clientpriv;  // clients private key
    

    public static void main(String[] args) throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        try{
        Client client = new Client();
        client.run();

        }
        catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }

    }
    public void run() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        try{
            Scanner scan = new Scanner(System.in);

            s = new Socket("localhost",4999);
            pr = new PrintWriter(s.getOutputStream());
            
            /*BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        	String str = br.readLine();
            System.out.println("Server: " + str);*/
            this.CreateKeys();   // creating public and private keys for client
            System.out.println("Public-Private key pair created for client");
            
            while(s.isConnected()){ 	
	            System.out.println("Enter a message:");
	            String original = scan.nextLine();
	            String hashedMsg = sha1(original);         // hashing input from user
	            
	            System.out.println("Hashing message...");
	            System.out.println(original + " = " + hashedMsg);
	            System.out.println("Encrypting the hash...");
	            
	            byte[] signedHash = this.rsaSigning(hashedMsg.getBytes()); // encrypting the hash
	            //need to append encrypted hash to actual message then zip it.
	            System.out.println("Concatenating original message with encrypted hash (Separated by a \"+\")...");
	            String messageAndSignedHash = original+"+"+signedHash.toString(); // concatenating encrypted hash to the original message.
	            

                System.out.print("Original message and signed hash: ");
                System.out.println(messageAndSignedHash);
	            this.SaveToZip("ClientMessage.txt", messageAndSignedHash); // zipped client message



                // TAEO: 
                // 0. Generate Ks - DONE
                // 1. Encrypt the Z using Ks - DONE, JUST COMBINE CODES
                // 2. Encrypt Ks using public key encryption - Ks IS A FILE, ENCRYPT THE SAME WAY A HASH MASGS
                // Send 1 and 2 to server using pr.println() - SEND AND TEST IF FILES RECEIVED BY SERVER ARE VALID.
                // Write small program to test if files can be sent to server
                // done!!!
	            
	            pr.println(messageAndSignedHash);	// in the end this should send the encrypted zip file to the server
	            //System.out.println("Encrypted hash sent to server");
	            pr.flush();
            }
            s.close();
            scan.close();
        } 
        catch(IOException e){
            e.printStackTrace();
        }
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
    
    // No need for this method now
    /*
    public byte[] rsaEncryption(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    	PublicKey pubkey = GenerateRSAKeys.readPublicKeyFromFile("Pubkey.txt");	//public key obtained from file that server created, true if public read
    	Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.ENCRYPT_MODE, pubkey);
    	byte[] cipherData = cipher.doFinal(data);
    	return cipherData;    	
    }*/

/// Gareth was suppose to do the encryption using the private key not public key to sign
    public byte[] rsaSigning(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clientpriv);   // changed this to encrypt hash using clients private key
        byte[] cipherData = cipher.doFinal(data);
        return cipherData;      
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
     public void CreateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	this.clientside = new GenerateRSAKeys(2);	// creates a public and a private key
    	
    	Key[] keyring = new Key[2];			// position 0 has public key, position 1 has private key
    	keyring = clientside.KeyPairGen(2048);
    	this.clientkey = (PublicKey) keyring[0];
        this.clientside.getKeySpec("PubkeyClient.txt",this.clientkey);	// saves public key to a file called pubkey
    	this.clientpriv = (PrivateKey) keyring[1];
    }
}