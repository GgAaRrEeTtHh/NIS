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
//import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class Client{

    Socket s;
    PrintWriter pr;
    GenerateRSAKeys clientside;
    PublicKey clientkey;
    

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
            
            while(s.isConnected()){        	
                
	            System.out.println("Enter a message:");
	            String original = scan.nextLine();
	            String hashedMsg = sha1(original);         // hashing input from user
	            
	            System.out.println("Hashing current message...");
	            System.out.println(original + " = " + hashedMsg);
	            System.out.println("Encrypting the hash...");
	            
	            byte[] encryptedHash = this.rsaEncryption(hashedMsg.getBytes()); // encrypting the hash
	            //need to append encrypted hash to actual message then zip it.
	            String messageAndHash = original+"+"+encryptedHash.toString(); // concatenating encrypted hash to the original message.
	            
	            this.SaveToZip("ClientMessage.txt", messageAndHash); // zipped client message
	            
	            pr.println(messageAndHash);	// in the end this should send the encrypted zip file to the server
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
    
    public byte[] rsaEncryption(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    	PublicKey pubkey = GenerateRSAKeys.readKeyFromFile("Pubkey.txt");	//public key obtained from file that server created
    	Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.ENCRYPT_MODE, pubkey);
    	byte[] cipherData = cipher.doFinal(data);
    	return cipherData;    	
    }
    
    // used to save the final message as a zip file
    public void SaveToZip(String filename, String message) throws IOException {
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
}