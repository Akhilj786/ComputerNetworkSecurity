package ssl;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class C_Handshake {

    static Socket echoSocket = null;
    static DataOutputStream out = null;
    static DataInputStream in = null;
    
    static byte key_enc1[] = new byte[8];
    static byte key_enc2[] = new byte[8];
    static byte key_int1[] = new byte[8];
    static byte key_int2[] = new byte[8];
    
    static int cipher_to_use;
    static SecureRandom random = new SecureRandom();

	public static void main(String[] args) throws IOException {

		String file_name, file_data = null, data;
        BufferedReader inputStream = null;

        try {
        	
            echoSocket = new Socket("localhost", 8888);
            out = new DataOutputStream(echoSocket.getOutputStream());
            in = new DataInputStream(echoSocket.getInputStream());

        } catch (UnknownHostException e) {
            System.err.println("Could not connect to the Server. Unknown Exception.");
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Could not connect to the Server. I/O Exception.");
            System.exit(1);
        }

        System.out.println("Client Side: ");
        System.out.println();

        establishConnection();
        
		System.out.println("Enter the name of the file you want to transfer : ");
		Scanner s = new Scanner(System.in);
		file_name = s.nextLine();
		
		inputStream = new BufferedReader(new FileReader(file_name));
		//outputStream = new BufferedWriter(new FileWriter(file_name));
		
		while((data = inputStream.readLine())!=null)
		{
			if(file_data == null)
				file_data = data;
			else
				file_data = file_data + '\n' + data;
		}
		
		System.out.println("Data being transmitted : ");
		System.out.println(file_data);
		
		sendData(file_data,cipher_to_use);
		
		System.out.println("File Transfered");
		
		inputStream.close();
        out.close();
        in.close();
        echoSocket.close();
        
        System.out.println("Connection Closed.");
        
        System.out.println("Press 'y' to Establish Connection.");
        String ch = s.nextLine();
        if(!ch.equals("y"))
        	System.exit(1);
        
        System.out.println();
        System.out.println("Opening Connection.");
        
        file_data = null;
        
        try {
        	
            echoSocket = new Socket("localhost", 8888);
            out = new DataOutputStream(echoSocket.getOutputStream());
            in = new DataInputStream(echoSocket.getInputStream());

        } catch (UnknownHostException e) {
            System.err.println("Could not connect to the Server. Unknown Exception.");
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Could not connect to the Server. I/O Exception.");
            System.exit(1);
        }

        resumeConnection();
        
		System.out.println("Enter the name of the file you want to transfer : ");
		file_name = s.nextLine();
		
		inputStream = new BufferedReader(new FileReader(file_name));
		//outputStream = new BufferedWriter(new FileWriter(file_name));
		
		while((data = inputStream.readLine())!=null)
		{
			if(file_data == null)
				file_data = data;
			else
				file_data = file_data + '\n' + data;
		}
		
		System.out.println("Data being transmitted : ");
		System.out.println(file_data);
		
		sendData(file_data,cipher_to_use);
		
		System.out.println("File Transfered");
		
		inputStream.close();
        out.close();
        in.close();
        echoSocket.close();
        
        System.out.println("Connection Closed.");
	}
	
	public static void establishConnection() throws IOException{
		
		String ciphers = "Ciphers I support : 1.) 3DES/CFB 2.) 3DES/CBC 3.) 3DES/PCBC 4.) RC4";
        String message[];
        String messages;
		
		byte temp_message[];
        byte RA[] = new byte[32];
        byte RB[]= new byte[32];
        byte k[] = new byte[16];
        byte keyhash[] = new byte[16];
        byte keyhash2[] = new byte[16];
        byte concatedStr[] = new byte[96];
        
        byte key_enc[] = new byte[16];
        byte key_int[] = new byte[16];
        
        int rsa_e,rsa_n,len;
        
        random.nextBytes(RA);
        random.nextBytes(Storage.S);
        
        for(int i=0;i<32;i++)
        {
        	if(Storage.S[i]>-10&&Storage.S[i]<0)
        		Storage.S[i]+=10;
        }
        
        MessageDigest md = null;
        
        try {
        	
			md = MessageDigest.getInstance("MD5");
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
        /*
         * Send Message 1 - 
         * 1) Ciphers supported by Alice
         * 2) RAlice
         */
        
        temp_message = (ciphers + ",").getBytes();
        		
        byte[] sendMessage = new byte[temp_message.length + RA.length];
        System.arraycopy(temp_message, 0, sendMessage, 0, temp_message.length);
        System.arraycopy(RA, 0, sendMessage , temp_message.length, RA.length);
        
        messages = new String(sendMessage);
        
        out.writeInt(sendMessage.length);
        out.write(sendMessage);
        		
        System.out.println("Client -> Server (Msg 1) : " + new String(sendMessage));
        
        /*
         * Receive Message 2 - 
         * 1) session_id
         * 2) certificate - e and n
         * 3) Cipher Bob chooses 
         * 2) RBob
         */

        len = in.readInt();
        
        byte[] receiveMessage = new byte[len];
        in.readFully(receiveMessage);

        messages = messages + new String(receiveMessage);
        System.arraycopy(receiveMessage, (len-32), RB ,0, 32);
   		System.out.println("Server -> Client (Msg 2) : " + new String(receiveMessage)); 
       		
   		message = new String(receiveMessage).split(",");

   		Storage.session_id = Integer.parseInt(message[0]);

       	rsa_e = Integer.parseInt(message[1]);
       	rsa_n = Integer.parseInt(message[2]);
       		
       	cipher_to_use = Integer.parseInt(message[3]);
       		
   		System.arraycopy(Storage.S, 0, concatedStr, 0, 32);
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

   		System.out.println("Pre-Master Key : " + new String(Storage.S));
   		System.out.println("Master Key : " + new String(k));

   		/*
         * Send Message 3 - 
         * 1) S encrypted with Bob's Public Key
         * 2) Key hash of previous messages encrypted and integrity protected with K
         */
   		
   		//Encrypting S using RSA
   		temp_message = RSA.encrypt(rsa_e, rsa_n, Storage.S);

   		//Keyed Hash
   		keyhash = HMAC(new String(k),messages);
   		
   		//Generating the Message
        sendMessage = new byte[temp_message.length + keyhash.length];
        
        System.arraycopy(temp_message, 0, sendMessage, 0, temp_message.length);
        System.arraycopy(keyhash, 0, sendMessage , temp_message.length, keyhash.length);
        
        out.writeInt(sendMessage.length);
        out.write(sendMessage);
   		
   		messages = messages + new String(sendMessage);
        System.out.println("Client -> Server (Msg 3) : " + new String(sendMessage));
        
        /*
         * Receive Message 4 - 
         * 1) Key hash of previous messages encrypted and integrity protected with K
         */
        
        len = in.readInt();
        receiveMessage = new byte[len];
        in.readFully(receiveMessage);

        System.out.println("Server -> Client (Msg 4) : " + new String(receiveMessage));
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

	public static void resumeConnection() throws IOException{
		
		String ciphers = "Ciphers I support : 1.) 3DES/CFB 2.) 3DES/CBC 3.) 3DES/PCBC 4.) RC4";
        String message[];
        String messages;
		
		byte temp_message[];
        byte RA[] = new byte[32];
        byte RB[]= new byte[32];
        byte k[] = new byte[16];
        byte keyhash[] = new byte[16];
        byte keyhash2[] = new byte[16];
        byte concatedStr[] = new byte[96];
        
        byte key_enc[] = new byte[16];
        byte key_int[] = new byte[16];
        
        int len;
        
        random.nextBytes(RA);
        
        MessageDigest md = null;
        
        try {
        	
			md = MessageDigest.getInstance("MD5");
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
        /*
         * Send Message 1 - 
         * 1) Session_ID 
         * 2) Ciphers supported by Alice
         * 3) RAlice
         */
        
        temp_message = (Storage.session_id + "," + ciphers + ",").getBytes();
        		
        byte[] sendMessage = new byte[temp_message.length + RA.length];
        System.arraycopy(temp_message, 0, sendMessage, 0, temp_message.length);
        System.arraycopy(RA, 0, sendMessage , temp_message.length, RA.length);
        
        messages = new String(sendMessage);
        
        out.writeInt(sendMessage.length);
        out.write(sendMessage);
        		
        System.out.println("Client -> Server (Msg 1) : " + new String(sendMessage));
        
        /*
         * Receive Message 2 - 
         * 1) session_id
         * 2) Cipher Bob chooses 
         * 3) RBob
         * 4) Keyed Hash
         */

        int session;
        
        len = in.readInt();
        
        byte[] receiveMessage = new byte[len];
        in.readFully(receiveMessage);

        System.out.println("Server -> Client (Msg 2) : " + new String(receiveMessage));
        
        System.arraycopy(receiveMessage, (len-16), keyhash2, 0, 16);
        System.arraycopy(receiveMessage, (len-48), RB, 0, 32);
        
        message = new String(receiveMessage).split(",");
        
        session = Integer.parseInt(message[0]);
        
        if(session!=Storage.session_id)
        {
        	System.out.println("Server sent a different session_id. Exiting.");
        	System.exit(1);
        }
        else
        	System.out.println("Server remmebers session_id. Resuming session.");
        
        cipher_to_use = Integer.parseInt(message[1]);
        
   		System.arraycopy(Storage.S, 0, concatedStr, 0, 32);
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

   		System.out.println("Pre-Master Key : " + new String(Storage.S));
   		System.out.println("Master Key : " + new String(k));

   		//Generating keyed hash
   		keyhash = HMAC(new String(k),messages);
   		
   		//Comparing the keyed hashes
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
         * Send Message 3 - 
         * 1) Key hash of previous messages encrypted and integrity protected with K
         */
   		
   		//Keyed Hash
        keyhash = HMAC(new String(k),messages);
   		
	    //Generating the Message
        sendMessage = new byte[keyhash.length];
        System.arraycopy(keyhash, 0, sendMessage, 0, keyhash.length);
        
        out.writeInt(sendMessage.length);
        out.write(sendMessage);
   		
        System.out.println("Client -> Server (Msg 3) : " + new String(sendMessage));
        System.out.println("Data Transfer Begins");
	}
	
    public static void sendData(String file_data, int protocol) throws IOException{

    	byte original_IV[] = new byte[8];
		byte IV[] = new byte[8];
		byte cipher_text[] = null;
		int choice;
		
		String CBC_residue;
		SecureRandom random1 = new SecureRandom();
	    random1.nextBytes(original_IV);

	    byte[] mod_cipher_text = null; 
	    
	    System.out.println("Do you want to stimulate eavesdropper : ");
	    System.out.println("1) No 2) Modify ciphertext blocks 3) Remove ciphertext blocks 4) Add ciphertext blocks");
	    
		Scanner s = new Scanner(System.in);
		choice = Integer.parseInt(s.nextLine());
	    
	    for(int i=0;i<8;i++)
	    {
	    	IV[i] = original_IV[i];
	    }
    	
    	switch(protocol)
    	{
    	
    	case 1:
    		cipher_text = DESCFB.encrypt(new String(key_enc1), new String(key_enc2), IV, file_data);
    		break;
    	case 2:
    		CBC_residue = DESCBC.integrity(new String(key_int1), new String(key_int2), IV, file_data);
    		cipher_text = CBC_residue.getBytes();
    		break;
    	case 3:
    		cipher_text = PCBC.encrypt(new String(key_enc1), new String(key_enc2), IV, file_data);
    		break;
    	case 4:
    		cipher_text = RC4.encrypt(new String(key_enc1), file_data);
    		break;
    	}
    	
    	for(int i=0;i<8;i++)
	    {
	    	IV[i] = original_IV[i];
	    }
    	
    	if(protocol==2)
    	{
    		
    		switch(choice)
    		{
    		case 1:
    			break;
    		case 2:
    			mod_cipher_text = new byte[file_data.length()];
    			System.arraycopy(file_data.getBytes(), 0, mod_cipher_text, 0, file_data.length());
    			for(int i=0;i<8;i++)
    				mod_cipher_text[i]++;
    			
    			file_data = new String(mod_cipher_text);
    			break;
    		case 3:
    			mod_cipher_text = new byte[file_data.length()-8]; 
    			System.arraycopy(file_data.getBytes(), 8, mod_cipher_text, 0, file_data.length()-8);
    			file_data = new String(mod_cipher_text);
    			break;
    		case 4:
    			mod_cipher_text = new byte[file_data.length()+8]; 
    			System.arraycopy(file_data.getBytes(), 0, mod_cipher_text, 0, 8);
    			System.arraycopy(file_data.getBytes(), 0, mod_cipher_text, 8, file_data.length());
    			file_data = new String(mod_cipher_text);
    			break;
    		}

    		
    		file_data = file_data + ",#,";
    		
    		byte[] sendMessage = new byte[file_data.length() + cipher_text.length + IV.length];
    		System.arraycopy(file_data.getBytes(), 0, sendMessage, 0, file_data.length());
        	System.arraycopy(cipher_text, 0, sendMessage, file_data.length(), cipher_text.length);
        	System.arraycopy(IV, 0, sendMessage , cipher_text.length + file_data.length(), IV.length);
    	
        	out.writeInt(sendMessage.length);
        	out.write(sendMessage);
    	
        	System.out.println("Client -> Server (Data) : " + new String(sendMessage));
    	}
    	else
    	{
    		switch(choice)
    		{
    		case 1:
    			mod_cipher_text = new byte[cipher_text.length];
    			System.arraycopy(cipher_text, 0, mod_cipher_text, 0, cipher_text.length);
    			break;
    		case 2:
    			mod_cipher_text = new byte[cipher_text.length];
    			System.arraycopy(cipher_text, 0, mod_cipher_text, 0, cipher_text.length);
    			for(int i=0;i<8;i++)
    				mod_cipher_text[i]++;
    			break;
    		case 3:
    			mod_cipher_text = new byte[cipher_text.length-8]; 
    			System.arraycopy(cipher_text, 8, mod_cipher_text, 0, cipher_text.length-8);
    			break;
    		case 4:
    			mod_cipher_text = new byte[cipher_text.length+8]; 
    			System.arraycopy(cipher_text, 0, mod_cipher_text, 0, 8);
    			System.arraycopy(cipher_text, 0, mod_cipher_text, 8, cipher_text.length);
    			break;
    		}
    		
    		byte[] sendMessage = new byte[mod_cipher_text.length + IV.length];
        	System.arraycopy(mod_cipher_text, 0, sendMessage, 0, mod_cipher_text.length);
        	System.arraycopy(IV, 0, sendMessage , mod_cipher_text.length, IV.length);
    	
        	out.writeInt(sendMessage.length);
        	out.write(sendMessage);
    	
        	System.out.println("Client : " + new String(sendMessage));
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
