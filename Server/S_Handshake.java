package ssl;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
 
public class S_Handshake {
	
	static Socket clientSocket = null;
	static DataOutputStream out = null;
	static DataInputStream in = null;
	static BufferedReader keyRead = null;

	static byte key_enc1[] = new byte[8];
	static byte key_enc2[] = new byte[8];
	static byte key_int1[] = new byte[8];
	static byte key_int2[] = new byte[8];
	
	static String cipher_ip;
	
	static SecureRandom random = new SecureRandom();
	static Storage strg = new Storage();
	
    public static void main(String[] args) throws IOException {
 
        ServerSocket serverSocket = null; 
        int len;
        
        try {
            serverSocket = new ServerSocket(8888);
        } catch (IOException e) {
            System.err.println("Could not listen on port: 8888.");
            System.exit(1);
        }
 
        try {
        	clientSocket = serverSocket.accept();
        } catch (IOException e) {
        	System.err.println("Accept failed.");
        	System.exit(1);
        }
 
        out = new DataOutputStream(clientSocket.getOutputStream());
        in = new DataInputStream(clientSocket.getInputStream());
        keyRead = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Server Side: ");
        System.out.println();
        
        len = in.readInt();
        if(len==100)
        	establishConnection(len);
        else
        	resumeConnection(len);
        
        receiveData(Integer.parseInt(cipher_ip));
        
       	out.close();
      	in.close();
        clientSocket.close();
        
        System.out.println("Connection Closed.");
        
        try {
        	clientSocket = serverSocket.accept();
        } catch (IOException e) {
        	System.err.println("Accept failed.");
        	System.exit(1);
        }
 
        out = new DataOutputStream(clientSocket.getOutputStream());;
        in = new DataInputStream(clientSocket.getInputStream());;
        keyRead = new BufferedReader(new InputStreamReader(System.in));
        
        System.out.println();
        System.out.println("Opening Connection.");

        len = in.readInt();
        
        if(len==100)
        	establishConnection(len);
        else
        	resumeConnection(len);
        
        receiveData(Integer.parseInt(cipher_ip));
        
       	out.close();
      	in.close();
        clientSocket.close();
        serverSocket.close();
        
        System.out.println("Connection Closed.");
    }
    
    public static void establishConnection(int len) throws IOException{

    	byte temp_message[];
        byte RA[] = new byte[32];
        byte RB[]= new byte[32];
        byte k[] = new byte[16];
        byte keyhash[] = new byte[16];
        byte keyhash2[] = new byte[16];
        byte concatedStr[] = new byte[96];
        
        byte key_enc[] = new byte[16];;
        byte key_int[] = new byte[16];
        
        String messages;
        
        int rsa_e = 5,rsa_d = 173,rsa_n = 247;
        
        MessageDigest md = null;
        
        try {
        	
			md = MessageDigest.getInstance("MD5");
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
        random.nextBytes(RB);
        strg.new_session_id();
    	
        /*
         * Receive Message 1 - 
         * 1) Ciphers supported by Alice
         * 2) RAlice
         */
        
        byte[] receiveMessage = new byte[len];
        in.readFully(receiveMessage);
        
        messages = new String(receiveMessage);
        System.arraycopy(receiveMessage, (len-32), RA ,0, 32);
        
   		System.out.println("Client -> Server (Msg 1) : " + messages);
        System.out.println("Which Cipher do you want to use : ");
        cipher_ip = keyRead.readLine();
   		
        /*
         * Send Message 2 - 
         * 1) session_id
         * 2) certificate - e and n
         * 3) Cipher Bob chooses - Encryption and Integrity 
         * 2) RBob
         */
        
        temp_message = (strg.session_id + "," + rsa_e + "," + rsa_n + "," + cipher_ip + ",").getBytes();
        byte[] sendMessage = new byte[temp_message.length + RB.length];
        System.arraycopy(temp_message, 0, sendMessage, 0, temp_message.length);
        System.arraycopy(RB, 0, sendMessage , temp_message.length, RB.length);
        out.writeInt(sendMessage.length);
        out.write(sendMessage);
        
        messages =  messages + new String(sendMessage);
        
        System.out.println("Server -> Client (Msg 2) : " + new String(sendMessage));
        
        /*
         * Receive Message 3 - 
         * 1) S encrypted with Bob's Public Key
         * 2) Key hash of previous messages encrypted and integrity protected with K
         */
        
        len = in.readInt();
        receiveMessage = new byte[len];
        in.readFully(receiveMessage);

        System.out.println("Client -> Server (Msg 3) : " + new String(receiveMessage));
        
        System.arraycopy(receiveMessage, 32, keyhash2, 0, 16);
        System.arraycopy(receiveMessage, 0, strg.S , 0, 32);
        
        strg.S = RSA.decrypt(rsa_d, rsa_n, strg.S);
        
        //Generating k
        System.arraycopy(strg.S, 0, concatedStr, 0, 32);
   		System.arraycopy(RA, 0, concatedStr, 32, 32);
   		System.arraycopy(RB, 0, concatedStr, 64, 32);
   		
   		k = md.digest(concatedStr);
   		
   		concatedStr = new byte[17];
   		byte[] gen = new byte[]{1,2};
   		
   		//Generating Encryption keys
   		System.arraycopy(k, 0, concatedStr, 0, 16);
   		System.arraycopy(gen, 0, concatedStr, 16, 1);

   		key_enc = md.digest(concatedStr);
   		
   		System.arraycopy(key_enc, 0, key_enc1, 0, 8);
   		System.arraycopy(key_enc, 8, key_enc2, 0, 8); 

   		//Generating Integrity keys
   		System.arraycopy(k, 0, concatedStr, 0, 16);
   		System.arraycopy(gen, 1, concatedStr, 16, 1);

   		key_int = md.digest(concatedStr);
   		
   		System.arraycopy(key_int, 0, key_int1, 0, 8);
   		System.arraycopy(key_int, 8, key_int2, 0, 8); 

   		System.out.println("Pre-Master Key : " + new String(strg.S));
   		System.out.println("Master Key : " + new String(k));

        //Generating keyed hash
   		keyhash = HMAC(new String(k),messages);
   		
   		if(Arrays.equals(keyhash,keyhash2))
   		{
   			System.out.println("Keyed Hash is matching");
   		}
   		else
   		{
   			System.out.println("Keyed Hash is not matching.");
   		}
   		messages = messages + new String(receiveMessage);

   		/*
         * Send Message 4 - 
         * 1) Key hash of previous messages encrypted and integrity protected with K
         */
   		
   		//Generating keyed hash
   		keyhash = HMAC(new String(k),messages);
   		
	    //Generating the Message
        sendMessage = new byte[keyhash.length];
        
        System.arraycopy(keyhash, 0, sendMessage , 0, keyhash.length);
        
        out.writeInt(sendMessage.length);
        out.write(sendMessage);
   		
        System.out.println("Server -> Client (Msg 4) : " + new String(sendMessage));
        
        System.out.println("Data Transfer Begins");
    }

    public static void resumeConnection(int len) throws IOException{

    	byte temp_message[];
        byte RA[] = new byte[32];
        byte RB[]= new byte[32];
        byte k[] = new byte[16];
        byte keyhash[] = new byte[16];
        byte concatedStr[] = new byte[96];
        
        byte key_enc[] = new byte[16];;
        byte key_int[] = new byte[16];
        
        String messages;
        String message[];
        int session;
        
        MessageDigest md = null;
        
        try {
        	
			md = MessageDigest.getInstance("MD5");
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
        random.nextBytes(RB);
    	
        /*
         * Receive Message 1 -
         * 1) session_ID  
         * 2) Ciphers supported by Alice
         * 3) RAlice
         */
        
        byte[] receiveMessage = new byte[len];
        in.readFully(receiveMessage);
        
        messages = new String(receiveMessage);
        System.out.println("Client -> Server (Msg 1) : " + messages);
        
        System.arraycopy(receiveMessage, (len-32), RA ,0, 32);
        
   		message = new String(receiveMessage).split(",");
   		session = Integer.parseInt(message[0]);
        
   		if(session!=strg.session_id)
   		{
   			System.out.println("Server does not have this session id. Exiting");
   			System.exit(1);
   		}
   		else
   			System.out.println("Server has this session id. Resuming Session.");
   		
   		System.out.println(message[1]);
        System.out.println("Which Cipher do you want to use : ");
        cipher_ip = keyRead.readLine();
   		
        /*
         * Send Message 2 - 
         * 1) session_id
         * 2) Cipher Bob chooses - Encryption and Integrity 
         * 3) RBob
         * 4) Keyed Hash
         */
        
        //Generating k
        System.arraycopy(strg.S, 0, concatedStr, 0, 32);
   		System.arraycopy(RA, 0, concatedStr, 32, 32);
   		System.arraycopy(RB, 0, concatedStr, 64, 32);
   		
   		k = md.digest(concatedStr);
   		
   		concatedStr = new byte[17];
   		byte[] gen = new byte[]{1,2};
   		
   		//Generating Encryption keys
   		System.arraycopy(k, 0, concatedStr, 0, 16);
   		System.arraycopy(gen, 0, concatedStr, 16, 1);

   		key_enc = md.digest(concatedStr);
   		
   		System.arraycopy(key_enc, 0, key_enc1, 0, 8);
   		System.arraycopy(key_enc, 8, key_enc2, 0, 8); 

   		//Generating Integrity keys
   		System.arraycopy(k, 0, concatedStr, 0, 16);
   		System.arraycopy(gen, 1, concatedStr, 16, 1);

   		key_int = md.digest(concatedStr);
   		
   		System.arraycopy(key_int, 0, key_int1, 0, 8);
   		System.arraycopy(key_int, 8, key_int2, 0, 8); 

   		System.out.println("Pre-Master Key : " + new String(strg.S));
   		System.out.println("Master Key : " + new String(k));

        //Generating keyed hash
   		keyhash = HMAC(new String(k),messages);

   		temp_message = (strg.session_id + "," + cipher_ip + ",").getBytes();
        
        byte[] sendMessage = new byte[temp_message.length + RB.length + keyhash.length];
        System.arraycopy(temp_message, 0, sendMessage, 0, temp_message.length);
        System.arraycopy(RB, 0, sendMessage , temp_message.length, RB.length);
        System.arraycopy(keyhash, 0, sendMessage , temp_message.length + RB.length, keyhash.length);
        out.writeInt(sendMessage.length);
        out.write(sendMessage);
        
        messages =  messages + new String(sendMessage);
        
        System.out.println("Server -> Client (Msg 2) : " + new String(sendMessage));
        
        /*
         * Receive Message 3 - 
         * 1) Key hash of previous messages encrypted and integrity protected with K
         */
        
        len = in.readInt();
        receiveMessage = new byte[len];
        in.readFully(receiveMessage);

        System.out.println("Client -> Server (Msg 3) : " + new String(receiveMessage));

        byte keyhash2[] = new byte[len];
        
        System.arraycopy(receiveMessage, 0, keyhash2, 0, len);
        
        //Generating keyed hash
        keyhash = HMAC(new String(k),messages);
        
   		if(Arrays.equals(keyhash,keyhash2))
   		{
   			System.out.println("Keyed Hash is matching");
   		}
   		else
   		{
   			System.out.println("Keyed Hash is not matching.");
   		}
   		
        System.out.println("Data Transfer Begins");
    }
   
    public static void receiveData(int protocol) throws IOException{
    	
    	String answer = null,file_data = null,CBC_residue = null;
    	String[] temp;
    	
    	int len;
    	
    	boolean integrity;

    	byte IV[] = new byte[8];
		byte cipher_text[];
    	
    	len = in.readInt();
    	byte[] receiveMessage = new byte[len];
        in.readFully(receiveMessage);

        cipher_text = new byte[len-8];
        
        System.out.println("Client -> Server (Data) : " + new String(receiveMessage));
        
        System.arraycopy(receiveMessage, len-IV.length, IV, 0, IV.length);
        System.arraycopy(receiveMessage, 0, cipher_text, 0, len-IV.length);
        
        if(protocol==2)
        {
            temp = new String(cipher_text).split(",#,");
            file_data = temp[0];
            CBC_residue = temp[1];
        }
        
        switch(protocol)
    	{
    	
    	case 1:
    		answer = DESCFB.decrypt(new String(key_enc1), new String(key_enc2), IV, cipher_text);
    		break;
    	case 2:
    		integrity = DESCBC.check_integrity(new String(key_int1), new String(key_int2), IV, file_data, CBC_residue);
    	    if(integrity)
    	    	System.out.println("Message has not been tampered with.");
    	    else
    	    	System.out.println("Message has been tampered with.");
    		break;
    	case 3:
    		answer = PCBC.decrypt(new String(key_enc1), new String(key_enc2), IV, cipher_text);
    		break;
    	case 4:
    		answer = RC4.decrypt(new String(key_enc1), cipher_text);
    		break;
    	}
        
        if(protocol!=2)
        {
        	System.out.println("Data Received : ");
        	System.out.println(answer);
        }
    }

    public static byte[] HMAC(String key, String message){

    	int i;
    	
    	byte k[] = new byte[512];
    	byte k1[] = new byte[512];
    	byte keyhash[] = new byte[16];
    	byte b[] = new byte[56];
    	byte const1 = (byte) 00110110;
    	byte const2 = (byte) 01011100;
    	
    	MessageDigest md = null;
        
        try {
        	
			md = MessageDigest.getInstance("MD5");
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
    	
    	for(i=0;i<56;i++)
    		b[i]=0;
        
        System.arraycopy(key.getBytes(), 0, k, 0, key.length());
        System.arraycopy(b, 0, k, key.length(), 56);
        
    	for(i=0;i<64;i++)
    		k1[i] = (byte) (k[i] ^ const1); 
    	
    	message = new String(k1) + message;
    	byte concatedStr[] = new byte[message.length()];
        concatedStr = message.getBytes();

   		keyhash = md.digest(concatedStr);    	
    	
   		for(i=0;i<64;i++)
    		k[i] = (byte) (k[i] ^ const2);
   		
   		message = new String(k) + new String(keyhash);
    	concatedStr = new byte[message.length()];
        concatedStr = message.getBytes();
   		
        keyhash = md.digest(concatedStr);
        
    	return keyhash;
    }
}	