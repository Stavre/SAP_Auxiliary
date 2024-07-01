package Day03_Symmetric.src.ro.ase.ism.sap.day3;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Test {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {
		
		
		//test ECB
		
		CipherECB.encrypt("src/main/java/Day03_Symmetric/msg.txt", "src/main/java/Day03_Symmetric/msg.enc", "password12345678", "AES");
		
		//example with a 256 bit key but with a block size of 128 bits
		//CipherECB.encrypt("msg.txt", "msg.enc", "password12345678password12345678", "AES");
		
		CipherECB.decrypt("src/main/java/Day03_Symmetric/msg.enc", "src/main/java/Day03_Symmetric/msg2.txt", "password12345678", "AES");
		
		//test CBC
		CipherCBC.encrypt("src/main/java/Day03_Symmetric/msg.txt", "src/main/java/Day03_Symmetric/msgCBC.enc", "password12345678", "AES");
		CipherCBC.decrypt("src/main/java/Day03_Symmetric/msgCBC.enc", "src/main/java/Day03_Symmetric/msg3.txt", "password12345678", "AES");
		
		System.out.println("Done.");
		
		//test CTR
		CipherCTR.encrypt("src/main/java/Day03_Symmetric/msg.txt", "src/main/java/Day03_Symmetric/msgCTR.enc", "password12345678", "AES");
		CipherCTR.decrypt("src/main/java/Day03_Symmetric/msgCTR.enc", "src/main/java/Day03_Symmetric/msg4.txt", "password12345678", "AES");
	
		//test CTS
		CipherCTS.encrypt("src/main/java/Day03_Symmetric/msg.txt", "src/main/java/Day03_Symmetric/msgCTS.enc", "password12345678", "AES");
		CipherCTS.decrypt("src/main/java/Day03_Symmetric/msgCTS.enc", "src/main/java/Day03_Symmetric/msg5.txt", "password12345678", "AES");
		
	}

}
