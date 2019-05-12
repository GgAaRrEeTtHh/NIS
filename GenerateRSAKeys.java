package clientServer;

//import java.io.BufferedOutputStream;
import java.io.BufferedReader;
//import java.io.FileNotFoundException;
//import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
//import java.io.InputStream;
//import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
//import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class GenerateRSAKeys{
	Key[] keyring;
	
	public GenerateRSAKeys(int Nokeys) {
		keyring = new Key[Nokeys];
	}
	
	// Obtains the public and private key for RSA encryption
	public Key[] KeyPairGen(int KeySize) throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(KeySize);
		KeyPair kp = kpg.generateKeyPair();
		Key pubKey = kp.getPublic();
		Key privKey = kp.getPrivate();
		
		keyring[0] = pubKey;
		keyring[1] = privKey;
		
		return keyring;
				
	}
	
	// This method gets the key specifications and saves it to a file for later use 
	public void getKeySpec(String filename, Key PubKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(PubKey,RSAPublicKeySpec.class);	// to get modulus and exponent of public key
		//RSAPrivateKeySpec priv = fact.getKeySpec(PrivKey,RSAPrivateKeySpec.class);	// to get modulus and exponent of private key
		
		SaveToFile(filename, pub.getModulus().toString(), pub.getPublicExponent().toString());
		//SaveToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
		
	}
	
	private void SaveToFile(String filename, String modulus, String exponent) throws IOException{
		//ObjectOutputStream out = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
		try {
			PrintWriter out = new PrintWriter(filename);
			out.println(modulus);
			out.println(exponent);
			out.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	// allows client to read public key from file
	public static PublicKey readKeyFromFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		String modulus;
		String exponent;
		BufferedReader buff = new BufferedReader(new FileReader(filename));
		
		
		//String line = buff.readLine();
		String[] comps = new String[2];
			
		for(int i=0;i<2;i++) {
				comps[i] = buff.readLine();
		}
			
		buff.close();
		modulus = comps[0];
		exponent = comps[1];
		//System.out.println(modulus + "\n" + exponent);
			
		BigInteger m = new BigInteger(modulus);		
		BigInteger e = new BigInteger(exponent);
			
		RSAPublicKeySpec keyspec = new RSAPublicKeySpec(m,e);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey pubKey = fact.generatePublic(keyspec);	// recreating public key from file
			
		return pubKey;
			
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		
		GenerateRSAKeys generation = new GenerateRSAKeys(2);
		Key[] keys = generation.KeyPairGen(2048);
		System.out.println(keys[0]);	// shows public key
		//System.out.println(keys[1]);	// shows private key
		
		Key pub = keys[0];
		generation.getKeySpec("MajorKey.txt", pub);
		System.out.println(GenerateRSAKeys.readKeyFromFile("MajorKey.txt"));
		
	}
}
