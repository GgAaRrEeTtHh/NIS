import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.zip.Deflater;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClientTest 
{
	 Client client;
	
	 @BeforeEach
	 void setUp() throws Exception
	 {
		 client = new Client(true);
	 }
	 
	 @Test
	    void createKeys() throws Exception
	 {
	        File file = new File("PubkeyClient.txt");
	        assertTrue(file.exists());

	        String content = new String(Files.readAllBytes(Paths.get("PubkeyClient.txt")));
	        assertTrue(content.isEmpty() == false);
	 }
	 
	 @Test
	 void sha1Test() throws Exception
	 {
		 String s1 = "abc";
		 MessageDigest mDigest = MessageDigest.getInstance("SHA1");
	     byte [] s2  = mDigest.digest(s1.getBytes());
	     assertTrue( Arrays.equals(s2, Client.sha1(s1)));  //(s2.equals(Client.sha1(s1)));
		 
	 }
	 
	@Test
	 void addTwoArrays() throws Exception
	 {

		 byte [] A= new String("abc").getBytes();
		 byte [] B= new String("def").getBytes();
		 
		 byte[] combined = new byte[A.length + B.length];
         System.arraycopy(A,0,combined,0         ,A.length);
         System.arraycopy(B,0,combined,A.length,B.length);
		
         assertTrue( Arrays.equals(combined, client.addTwoArrays(A, B)));
	 }
	
	@Test 
	void compressTest()
	{
		String s = "abc";
		byte[] bytes = s.getBytes();
		
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
		   
		   assertTrue( Arrays.equals(compressedArray, client.compress("abc".getBytes())));
	}
}
