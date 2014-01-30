package ssl;

public class RSA {
	public static byte[] encrypt(int e, int n, byte[] byte_plaintext) {
		
		int i,j,len;
		
		short ch,t;
		
    	len = byte_plaintext.length;
    	
    	byte[] cipher_text = new byte[len];
    	
    	//Encryption
    	for(i=0;i<len;i++)
    	{
    		ch = (short) ((short) byte_plaintext[i] & 0xff);
    		t = (short) ((ch * ch) % n); 
    		for(j=3;j<=e;j++)
    		{
    			t = (short) ((ch*t) % n);
    		}
    		cipher_text[i] = (byte) (t);
    	}

    	return cipher_text;
	}

	public static byte[] decrypt(int d, int n, byte[] cipher_text) {
		
		int i,j,len;
		short ch,t;
		
    	len = cipher_text.length;
    	
    	byte[] decrypted_text = new byte[len];
    	
    	//Decryption
    	for(i=0;i<len;i++)
    	{
    		ch = (short) ((short) cipher_text[i] & 0xff);
    		t = (short) ((ch * ch) % n); 
    		for(j=3;j<=d;j++)
    		{
    			t = (short) ((ch*t) % n);
    		}
    		decrypted_text[i] = (byte) (t);
    	}
    	
    	return decrypted_text;
	}

}
