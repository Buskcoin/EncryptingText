import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class TextEncrypt {
	public static void main(String[] args) throws Exception {
		Scanner kb = new Scanner(System.in);
		String ent = "";
		while(true){
			String line = kb.nextLine();
			if(line.equals("q"))
				break;
			else
				ent += line+"\n";
		}
		JournalEntry entry = new JournalEntry(new File("file.file"), ent);
		System.out.println("Enter password");
		String enc = entry.encryptEntry(kb.nextLine());
		System.out.println("Enter password");
		System.out.println(entry.decryptEntry(kb.nextLine(), enc));
	}

	public static class JournalEntry {
		private static final int KEY_LENGTH = 16;
		private static final SecureRandom RANDOM = new SecureRandom();

		private IvParameterSpec initializationVector;
		private Cipher cipher;
		private String entry;

		public JournalEntry(File file, String entry) throws GeneralSecurityException {
			this.entry = entry;
			this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			byte[] bytes = new byte[16];
			RANDOM.nextBytes(bytes);

			initializationVector = new IvParameterSpec(bytes);
		}
		
	

		public String encryptEntry(String key) throws GeneralSecurityException, UnsupportedEncodingException {
			cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(key), this.initializationVector);
			return new String(cipher.doFinal(this.entry.getBytes("ISO-8859-1")), "ISO-8859-1");
		}
		
		public String decryptEntry(String key, String encrypted) throws GeneralSecurityException, UnsupportedEncodingException {
			cipher.init(Cipher.DECRYPT_MODE, getSecretKey(key), this.initializationVector);
			return new String(cipher.doFinal(encrypted.getBytes("ISO-8859-1")), "ISO-8859-1");
		}

		private SecretKeySpec getSecretKey(String password)
				throws GeneralSecurityException, UnsupportedEncodingException {
			return getSecretKey(password.getBytes("ISO-8859-1"), initializationVector.getIV());
		}

		private SecretKeySpec getSecretKey(byte[] pwd, byte[] keyInitializationVector) throws GeneralSecurityException {
			byte[] key = new byte[KEY_LENGTH];
			int offset = 0;
			int bytesNeeded = KEY_LENGTH;

			MessageDigest md5 = MessageDigest.getInstance("MD5");
			while (true) {
				md5.update(pwd);
				md5.update(keyInitializationVector, 0, 8);

				byte[] b = md5.digest();
				int len = (bytesNeeded > b.length) ? b.length : bytesNeeded;

				System.arraycopy(b, 0, key, offset, len);
				offset += len;

				bytesNeeded = key.length - offset;
				if (bytesNeeded == 0) {
					break;
				}

				md5.reset();
				md5.update(b);
			}

			return new SecretKeySpec(key, "AES");
		}
	}
}
