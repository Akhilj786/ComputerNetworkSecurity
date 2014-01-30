package ssl;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class PCBC {

	public static byte[] encrypt(String key1, String key2, byte IV[], String plaintext) {

		byte[] byte_plaintext;
		byte[] block_encrypt = new byte[8];
			
		int i,j,k,len,pad_count,no_of_blocks;
			
		len = plaintext.length();
		pad_count = 8 - (len % 8);
			
		byte[] cipher_text = new byte[len+pad_count+8];
			
		plaintext = plaintext + "##";
		
		for(i=2;i<pad_count;i++)
			plaintext = plaintext + "0";		//Padding plaintext to a multiple of 8 bytes(64 bits)  
			
		plaintext = plaintext + "qwertyui";		//Concatinating with recognizable data for integrity protection
			
		byte_plaintext = plaintext.getBytes(); 
			
		no_of_blocks = (len + pad_count)/8;
		    			
		//Encryption
		for(i=0;i<=no_of_blocks;i++)
		{
			k=i*8;
			for(j=0;j<8;j++,k++)
			{
				block_encrypt[j] = (byte) (IV[j] ^ byte_plaintext[k]);
			}
				
			try {
				
				block_encrypt = encrypt(key1, key2, block_encrypt);
					
			} catch (Throwable e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
			k=i*8;
			for(j=0;j<8;j++,k++)
			{
				cipher_text[k] = block_encrypt[j];
				IV[j] = (byte) (block_encrypt[j] ^ byte_plaintext[k]);
			}
				
		}

		return cipher_text;
		
	}

	public static String decrypt(String key1, String key2, byte IV[], byte[] cipher_text) {

		byte[] block_encrypt = new byte[8];
		int i,j,k,len,no_of_blocks;
			
		len = cipher_text.length;  
			
		byte[] decrypted_text = new byte[len];
		String answer[];
			
		no_of_blocks = len/8;
		    			
		for(i=0;i<no_of_blocks;i++)
		{
			k=i*8;
			for(j=0;j<8;j++,k++)
			{
				block_encrypt[j] = cipher_text[k];
			}
				
			try {
					
				block_encrypt = decrypt(key1, key2, block_encrypt);
					
			} catch (Throwable e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
			k=i*8;
			for(j=0;j<8;j++,k++)
			{
				decrypted_text[k] = (byte) (block_encrypt[j] ^ IV[j]);
				IV[j] = (byte) (cipher_text[k] ^ decrypted_text[k]);
			}
		}


		if(!new String(decrypted_text).endsWith("qwertyui"))
			System.out.println("The message has been tampered with");
		
		answer = new String(decrypted_text).split("##");
			
		return answer[0];
	}
	
	public static byte[] encrypt(String key1, String key2 , byte[] byte_plaintext) throws Throwable
	{
		
		byte[] encrypted_text;
		
		DESKeySpec keyspec1 = new DESKeySpec(key1.getBytes());
		SecretKeyFactory key_fact1 = SecretKeyFactory.getInstance("DES");
		SecretKey DESkey1 = key_fact1.generateSecret(keyspec1);
		
		DESKeySpec keyspec2 = new DESKeySpec(key2.getBytes());
		SecretKeyFactory key_fact2 = SecretKeyFactory.getInstance("DES");
		SecretKey DESkey2 = key_fact2.generateSecret(keyspec2);

		//Cipher
		Cipher cipher1 = Cipher.getInstance("DES/ECB/NoPadding");
		Cipher cipher2 = Cipher.getInstance("DES/ECB/NoPadding");
		
		cipher1.init(Cipher.ENCRYPT_MODE, DESkey1);
		cipher2.init(Cipher.DECRYPT_MODE, DESkey2);
		
		encrypted_text = cipher1.doFinal(byte_plaintext);
		
		byte_plaintext = cipher2.doFinal(encrypted_text);
		
		encrypted_text = cipher1.doFinal(byte_plaintext);
		
		return encrypted_text; 
		
	}
	
	public static byte[] decrypt(String key1, String key2 , byte[] encrypted_text) throws Throwable
	{
		
		byte[] decrypted_text;
		
		DESKeySpec keyspec1 = new DESKeySpec(key1.getBytes());
		SecretKeyFactory key_fact1 = SecretKeyFactory.getInstance("DES");
		SecretKey DESkey1 = key_fact1.generateSecret(keyspec1);
		
		DESKeySpec keyspec2 = new DESKeySpec(key2.getBytes());
		SecretKeyFactory key_fact2 = SecretKeyFactory.getInstance("DES");
		SecretKey DESkey2 = key_fact2.generateSecret(keyspec2);

		Cipher cipher1 = Cipher.getInstance("DES/ECB/NoPadding");
		Cipher cipher2 = Cipher.getInstance("DES/ECB/NoPadding");

		cipher1.init(Cipher.DECRYPT_MODE, DESkey1);
		cipher2.init(Cipher.ENCRYPT_MODE, DESkey2);
		
		decrypted_text = cipher1.doFinal(encrypted_text);
		
		encrypted_text = cipher2.doFinal(decrypted_text);
		
		decrypted_text = cipher1.doFinal(encrypted_text);

		return decrypted_text;
		
	}
}
