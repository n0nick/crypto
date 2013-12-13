import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryptor {
	
	private Signature signature;
	private String signFile;
	
	private Cipher cipherAES;
	private SecretKey AESSecKey;
	
	private EncryptionParams params;

	public Encryptor(String keypass) {
		
		this.params = new EncryptionParams();

		try {
			params.keyGenType = "AES";

			params.ksType = "JCEKS";
			params.ksProvider = "SunJCE";

			params.AES_ALGORITHM_TYPE = "AES/CBC/PKCS5Padding";
			params.RSA_ALGORITHM_TYPE = "RSA";
			params.DSA_ALGORITHM_TYPE = "DSA";

			params.AES_CRYPT_PROVIDER = "SunJCE";
			params.RSA_CRYPT_PROVIDER = "SunJCE";
			params.DSA_CRYPT_PROVIDER = "SUN";
			signFile = "signature.txt";

			params.encryptorKeyName = "encryptor";
			params.encryptorKeyPass = "DJc8k7W9";

			params.decryptorKeyName = "decryptor";
			String decryptorKeyPass = "w043Ea-H";

			signature = Signature.getInstance("DSA");
			Cipher decode = Cipher.getInstance(params.AES_ALGORITHM_TYPE);
			KeyGenerator genAES = KeyGenerator.getInstance("AES");
			SecureRandom secRandom = new SecureRandom();
			secRandom.nextBytes(params.initVec);
			cipherAES = Cipher.getInstance(params.AES_ALGORITHM_TYPE);
			Cipher cipherRSA = Cipher.getInstance("RSA");
			AESSecKey = genAES.generateKey();
			KeyStore ks = KeyStore.getInstance(params.ksType);
			FileInputStream inputStream = new FileInputStream(
					Crypto.KEYSTORE_FILENAME);
			ks.load(inputStream, keypass.toCharArray());
			PrivateKey DSAPrivateKey = (PrivateKey) ks.getKey(params.decryptorKeyName,
					decryptorKeyPass.toCharArray());
			Certificate RSACertificate = ks.getCertificate(params.encryptorKeyName);

			cipherAES.init(Cipher.ENCRYPT_MODE, AESSecKey, new IvParameterSpec(
					params.initVec));
			decode.init(Cipher.DECRYPT_MODE, AESSecKey, new IvParameterSpec(
					params.initVec));
			cipherRSA.init(Cipher.ENCRYPT_MODE, RSACertificate);
			signature.initSign(DSAPrivateKey);
			cipherRSA.update(AESSecKey.getEncoded());
			params.encryptedKey = cipherRSA.doFinal();
		} catch (Exception e) {
			System.out.println("Error initializing: " + e.getMessage());
		}

	}

	public void encryptFile(String fileToEncrypt) throws Exception {

		params.encFile = fileToEncrypt + ".enc";
		FileInputStream fileInput = null;
		FileOutputStream fileOutput = null;
		BufferedWriter out = null;
		CipherOutputStream outputStream = null;
		try {
			byte[] readBuffer = new byte[8];
			int bytesRead;
			fileInput = new FileInputStream(fileToEncrypt);
			fileOutput = new FileOutputStream(fileToEncrypt + ".enc");

			// init the output stream to encrypt using the cipher output stream,
			// using AES algorithm
			outputStream = new CipherOutputStream(fileOutput, cipherAES);

			while ((bytesRead = fileInput.read(readBuffer)) != -1) {
				outputStream.write(readBuffer, 0, bytesRead);
				this.signature.update(readBuffer, 0, bytesRead);
			}

			// sign the file
			params.signResult = this.signature.sign();
			out = new BufferedWriter(new FileWriter(signFile));
			out.write(Integer.toString(params.signResult.length) + "\r\n");
			out.write(Arrays.toString(params.signResult) + "\r\n");
			
			params.writeToFile("config.txt");
		} finally {
			outputStream.close();
			fileInput.close();
			fileOutput.flush();
			fileOutput.close();
			out.close();
		}
	}
}
