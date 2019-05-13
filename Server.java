package clientServer;
import java.net.*;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
//import java.util.*;
import java.io.*;

public class Server {
    ServerSocket ss;
    Socket s;
    Key pub;
    Key priv;
    PrintWriter p;
    GenerateRSAKeys keygen;	//object to create and save RSA keys

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Server server = new Server();
        server.run();
    }

    public void run() throws NoSuchAlgorithmException, InvalidKeySpecException{
        
        try{
            ss = new ServerSocket(4999);
            
                System.out.println("Waiting for client");
                s = ss.accept();	// Accept client connection

                System.out.println("Client connected");	
                
                this.CreateKeys();	// Create private and public keys
                System.out.println("Public-Private key pair created");
                keygen.getKeySpec("Pubkey.txt",this.pub);	// saves public key to a file called pubkey
                System.out.println("Public key saved to file Pubkey.txt");
                
                
                while(s.isConnected()){
                BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            
                String str = br.readLine();
                System.out.println("Message + encrypted hash from client: " + str);

                if(str.equals("")){
                    break;
                }
            }      
                
        }
        catch(IOException e){
            e.printStackTrace();
        }
    }
    
    // Keys are created and then saved onto the server
    public void CreateKeys() throws NoSuchAlgorithmException {
    	this.keygen = new GenerateRSAKeys(2);	// creates a public and a private key
    	
    	Key[] keyring = new Key[2];			// position 0 has public key, position 1 has private key
    	keyring = keygen.KeyPairGen(2048);
    	this.pub = keyring[0];
    	this.priv = keyring[1];
    }
    
}

