import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils.IO;

public class SessionKeyGenerator 
{
	private SecretKey secretKey;
	
	public SessionKeyGenerator() throws Exception
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 128;

		keyGenerator.init(keyBitSize, secureRandom);
		
		secretKey = keyGenerator.generateKey();
	}
	
	public SecretKey getSessionKey()
	{
		return secretKey;
	}
	
	public void saveToFile(String filename) throws Exception
	{
		FileOutputStream f = new FileOutputStream(new File(filename));
	
		ObjectOutputStream o = new ObjectOutputStream(f);
	
		// Write session key objects to file
		o.writeObject(secretKey);
		
		o.close();
	}
	
	public SecretKey readFromFile(String filename) throws Exception
	{
		FileInputStream fi = new FileInputStream(new File(filename));
		ObjectInputStream oi = new ObjectInputStream(fi);

		// Read objects
		SecretKey sk = (SecretKey) oi.readObject();
		oi.close();
		return sk;
	}
}
