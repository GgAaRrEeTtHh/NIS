import java.net.*;
import java.util.*;
import java.io.*;

public class Server {
    ServerSocket ss;
    Socket s;

    public static void main(String[] args) throws IOException {
        Server server = new Server();
        server.run();
    }

    public void run(){
        
        try{
            ss = new ServerSocket(4999);
            
                System.out.println("Waiting for client");
                s = ss.accept();

                System.out.println("Client connected");

                while(s.isConnected()){
                BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));

            
                String str = br.readLine();
                System.out.println("Client: " + str);

                if(str.equals("")){
                    break;
                }
            }      
                
        }
        catch(IOException e){
            e.printStackTrace();
        }
    }
}

