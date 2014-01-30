package ssl;

public class RC4 {
	public static byte[] encrypt(String key, String plaintext) {

		byte[] b_key = key.getBytes();
		short[] s_key = new short[b_key.length];
			
		short[] S = new short[256];
		byte[] byte_plaintext;
			
		short temp,K;
		int i,x,l,j=0;
		int key_len,text_len;
			
    	text_len = plaintext.length();
    	byte_plaintext = plaintext.getBytes();
	    	
    	byte[] cipher_text = new byte[text_len];
		byte[] keystream = new byte[text_len];
	    	
		//Converting key from byte to short
    	for (x = 0; x < b_key.length; x++) 
    	{
            s_key[x] = (short) ((short) b_key[x] & 0xff);
        }
	    	
    	//Generating Keystream
    	key_len = b_key.length;
			
    	for(i=0;i<256;i++)
    	{
    		S[i]=(short)i;
    	}
	    	
    	for(i=0;i<256;i++)
    	{
    		j = (j + S[i] + s_key[i % key_len]) % 256;
    		temp = S[i];
    		S[i] = S[j];
    		S[j] = temp;
    	}
	    	
    	l=0;
    	j=0;
    	for(x=0;x<text_len;x++)
    	{
    		l = (l + 1) % 256;
    		j = (j + S[l]) % 256;
    		temp = S[l];
    		S[l] = S[j];
    		S[j] = temp;
		    K = S[(S[l] + S[j]) % 256];
		    keystream[x] = (byte) K;
		    cipher_text[x] = (byte) (byte_plaintext[x] ^ keystream[x]);			//Encrypting with the keystream 
    	}

    	return cipher_text;
    	
	}
	
	public static String decrypt(String key, byte[] cipher_text) {

		byte[] b_key = key.getBytes();
		short[] s_key = new short[b_key.length];
		
		short[] S = new short[256];
		
		short temp,K;
		int i,x,l,j=0;
		int key_len,text_len;
		
		text_len = cipher_text.length;
		
		byte[] keystream = new byte[text_len];
    	byte[] decrypted_text = new byte[text_len];
    	String answer;
    	
		//Converting key from byte to short
    	for (x = 0; x < b_key.length; x++) 
    	{
            s_key[x] = (short) ((short) b_key[x] & 0xff);
        }
    	
    	//Generating Keystream
    	key_len = b_key.length;
		
    	for(i=0;i<256;i++)
    	{
    		S[i]=(short)i;
    	}
    	
    	for(i=0;i<256;i++)
    	{
    		j = (j + S[i] + s_key[i % key_len]) % 256;
    		temp = S[i];
    		S[i] = S[j];
    		S[j] = temp;
    	}
    	
    	l=0;
    	j=0;
    	for(x=0;x<text_len;x++)
    	{
    		l = (l + 1) % 256;
    		j = (j + S[l]) % 256;
    		temp = S[l];
    		S[l] = S[j];
    		S[j] = temp;
			K = S[(S[l] + S[j]) % 256];
			keystream[x] = (byte) K;
			decrypted_text[x] = (byte) (cipher_text[x] ^ keystream[x]);			//Decrypting with the keystream 
    	}
    	
    	answer = new String (decrypted_text);
    	System.out.println("Decrypted Text : " + answer);
    	
    	return answer;
	}

}
