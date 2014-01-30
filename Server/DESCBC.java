package ssl;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class DESCBC {
	public static String integrity(String key1, String key2, byte IV[], String plaintext) {
		
		byte[] byte_plaintext;
		byte[] message_block = new byte[8];
		byte[] cipher_block = new byte[8];
		String cbc_residue;
			
		int i,j,k,len,pad_count,no_of_blocks;
		
		//Initializing the cipher block to 0
		for(i=0;i<8;i++)
			cipher_block[i]=0;
				
		len = plaintext.length();
		pad_count = 8 - (len % 8);
			
		plaintext = plaintext + "##";
				
		for(i=2;i<pad_count;i++)
		plaintext = plaintext + "0";		//Padding plaintext to a multiple of 8 bytes(64 bits)  
			
		byte_plaintext = plaintext.getBytes(); 
			
		no_of_blocks = (len + pad_count)/8;			//Number of 64 bit blocks
			
		for(i=0;i<no_of_blocks;i++)
		{
			k=i*8;
			for(j=0;j<8;j++,k++)
			{
				message_block[j] = (byte) (cipher_block[j] ^ byte_plaintext[k]);
			}
				
			try {
						
				cipher_block = encrypt(key1, key2, message_block);
						
			} catch (Throwable e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
				
		cbc_residue = new String(cipher_block);
		
		return cbc_residue; 
	}

	public static boolean check_integrity(String key1, String key2, byte IV[], String plaintext, String CBC_residue) {
			
		byte[] byte_plaintext;
		byte[] message_block = new byte[8];
		byte[] cipher_block = new byte[8];
		String cbc_residue_check;
				
		int i,j,k,len,pad_count,no_of_blocks;
			
		//Initializing the cipher block to 0
		for(i=0;i<8;i++)
			cipher_block[i]=0;
					
		len = plaintext.length();
		pad_count = 8 - (len % 8);
				
		plaintext = plaintext + "##";
					
		for(i=2;i<pad_count;i++)
		plaintext = plaintext + "0";		//Padding plaintext to a multiple of 8 bytes(64 bits)  
				
		byte_plaintext = plaintext.getBytes(); 
				
		no_of_blocks = (len + pad_count)/8;			//Number of 64 bit blocks
			
		for(i=0;i<no_of_blocks;i++)
		{
			k=i*8;
			for(j=0;j<8;j++,k++)
			{
				message_block[j] = (byte) (cipher_block[j] ^ byte_plaintext[k]);
			}
				
			try {
						
				cipher_block = encrypt(key1, key2, message_block);
						
			} catch (Throwable e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
				
		cbc_residue_check = new String(cipher_block);
		
		if(cbc_residue_check.equals(CBC_residue))
			return true;
		
		return false;
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
}

