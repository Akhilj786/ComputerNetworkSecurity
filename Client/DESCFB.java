package ssl;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class DESCFB {
	
	public static byte[] encrypt(String key1, String key2, byte IV[], String plaintext) {

		byte[] byte_plaintext;
		byte[] message_block = new byte[8];

		byte Encrypted_IV[] = new byte[8];
		byte[] temp_cipher = new byte[8];
			
		int i,j,k,len,pad_count,no_of_blocks;
		int block_size = 4;							//Size of k (in bytes) in k-bit CFB
			
		len = plaintext.length();
		pad_count = block_size - (len % block_size);
			
		plaintext = plaintext + "##";
		
		for(i=2;i<pad_count;i++)
			plaintext = plaintext + "0";		//Padding plaintext to a multiple of 8 bytes(64 bits)  
			
		byte[] cipher_text = new byte[len+pad_count];
		byte[] used_IV = new byte[len+pad_count];
			
		byte_plaintext = plaintext.getBytes(); 
			
		no_of_blocks = (len + pad_count)/block_size;		
			
		//Encryption
		for(i=0;i<no_of_blocks;i++)
		{
			try {
				
				Encrypted_IV = Triple_DES_encrypt(key1, key2, IV);
				
			} catch (Throwable e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
			k=i*block_size;
			for(j=0;j<block_size;j++,k++)
			{
				used_IV[k] = Encrypted_IV[j];				//Used_IV stores the part of Encrypted_IV used for encryption
				message_block[j] = byte_plaintext[k];
				cipher_text[k] = (byte) (Encrypted_IV[j] ^ message_block[j]);
				temp_cipher[j] = cipher_text[k];
			}
				
			//Left shifting IV
			
			for(k=block_size;k<8;k++)
			{
				IV[k-block_size] = IV[k];
			}
				
			//Concatinating block_size (k) bytes of Encrypted IV with left shifted IV
				
			k=block_size-1;
			int m=7;
			for(int l=0;l<block_size;l++)
			{
				IV[m]=temp_cipher[k];
				m--;
				k--;
			}
		}
			
		return cipher_text;
	}
	
	public static String decrypt(String key1, String key2, byte IV[], byte[] cipher_text) {

		byte Encrypted_IV[] = new byte[8];
		byte[] temp_cipher = new byte[8];
			
		int i,j,k,len,no_of_blocks;
		int block_size = 4;							//Size of k (in bytes) in k-bit CFB

		String answer[];
			
		len = cipher_text.length;
			
		byte[] decrypted_text = new byte[len];
		byte[] used_IV = new byte[len];
			
		no_of_blocks = len/block_size;		
			
		//Decryption
		for(i=0;i<no_of_blocks;i++)
		{
			try {
					
				Encrypted_IV = Triple_DES_encrypt(key1, key2, IV);
					
			} catch (Throwable e) {
			// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
			k=i*block_size;
			for(j=0;j<block_size;j++,k++)
			{
				used_IV[k] = Encrypted_IV[j];				//Used_IV stores the part of Encrypted_IV used for encryption
				temp_cipher[j] = cipher_text[k];
			}
				
			//Left shifting IV
				
			for(k=block_size;k<8;k++)
			{
				IV[k-block_size] = IV[k];
			}
				
			//Concatinating block_size (k) bytes of Encrypted IV with left shifted IV
				
			k=block_size-1;
			int m=7;
			for(int l=0;l<block_size;l++)
			{
				IV[m]=temp_cipher[k];
				m--;
				k--;
			}
		}

		for(i=0;i<len;i++)
		{
			decrypted_text[i] = (byte) (cipher_text[i] ^ used_IV[i]);
		}
		
		answer = new String(decrypted_text).split("##");

		return answer[0];
			
	}
	
	public static byte[] Triple_DES_encrypt(String key1, String key2 , byte[] byte_plaintext) throws Throwable
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
