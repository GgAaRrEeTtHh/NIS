import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Client{

    Socket s;
    PrintWriter pr;

    public static void main(String[] args) throws IOException{
        try{
        Client client = new Client();
        client.run();

        }
        catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }

    }
    public void run() throws NoSuchAlgorithmException{
        try{
            Scanner scan = new Scanner(System.in);

            s = new Socket("localhost",4999);
            pr = new PrintWriter(s.getOutputStream());

            while(s.isConnected()){
            System.out.println("Enter a message:");
            String msg = sha1(scan.nextLine());         // hashing input from user
            pr.println(msg);
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
}