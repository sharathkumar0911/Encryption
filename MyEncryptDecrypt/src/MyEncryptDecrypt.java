

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.*;

public class MyEncryptDecrypt {
    


public static String encrypt(String Data,String Key) throws Exception {
	String ALGO = "AES";
	if(Key.length()<16)
	{
		
		int Count=Key.length();
while(Count<=16)
	{
		
		Key=Key+"qwerty@123";
		
		Count=Key.length();
	}
	}
	
	if(Key.length()>16)
	{
		
		Key=Key.substring(0,16);
	
	}

	
	
	byte[] keyValue =Key.getBytes(); 
        Key key = generateKey(ALGO,keyValue);
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data.getBytes());
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue;
    }

    public static String decrypt(String encryptedData,String Key) throws Exception {
    	String ALGO = "AES";
    	
    	if(Key.length()<16)
    	{
    		int Count=Key.length();
    		while(Count<=16)
    			{
    				
    				Key=Key+"qwerty@123";
    				
    				Count=Key.length();
    			}
    	}
    
    	if(Key.length()>16)
    	{
    		
    		Key=Key.substring(0,16);
    		
    	}
    	
    	
    	
    	byte[] keyValue =Key.getBytes(); 
        Key key = generateKey(ALGO,keyValue);
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }
    private static Key generateKey(String ALGO,byte[]keyValue) throws Exception {
        Key key = new SecretKeySpec(keyValue, ALGO);
        return key;
}
    
    
    
    
    
public static void main(String[] args) throws Exception {

    	
        String password = "mypassword";
        String passwordEnc = MyEncryptDecrypt.encrypt(password,"12345");
        String passwordDec = MyEncryptDecrypt.decrypt(passwordEnc,"12345");

        System.out.println("Plain Text : " + password);
        System.out.println("Encrypted Text : " + passwordEnc);
        System.out.println("Decrypted Text : " + passwordDec);
    } 
    
    
    

}
