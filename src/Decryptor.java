import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor {

	public void decryptFile(String filename, String configurationFile) throws Exception {
		doWork("output.dec");
	}

	private Cipher AESCipher;
	private Signature signature;
	
	private EncryptionParams params;

	public Decryptor(String keypass) throws Exception {
		this.params = EncryptionParams.readFromFile("config.txt");
		
		AESCipher = Cipher.getInstance(params.AES_ALGORITHM_TYPE, params.AES_CRYPT_PROVIDER);
		Cipher RSACipher = Cipher.getInstance(params.RSA_ALGORITHM_TYPE, params.RSA_CRYPT_PROVIDER);
		signature = Signature.getInstance(params.DSA_ALGORITHM_TYPE, params.DSA_CRYPT_PROVIDER);
		KeyStore keyStore = KeyStore.getInstance(params.ksType,
				params.ksProvider);
		FileInputStream inputStream = new FileInputStream(Crypto.KEYSTORE_FILENAME);
		keyStore.load(inputStream, keypass.toCharArray());
		PrivateKey RSAPrivateKey = (PrivateKey) keyStore.getKey(params.encryptorKeyName,
				params.encryptorKeyPass.toCharArray());
		PublicKey DSAPublicKey = keyStore.getCertificate(params.decryptorKeyName).getPublicKey();
		RSACipher.init(Cipher.DECRYPT_MODE, RSAPrivateKey);
		signature.initVerify(DSAPublicKey);
		RSACipher.update(params.encryptedKey);
		byte[] temp = RSACipher.doFinal();
		SecretKey AESKey = new SecretKeySpec(temp, params.keyGenType);
		AESCipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(params.initVec));
	}

	public void doWork(String outputFile) throws Exception {

		byte[] buffer = new byte[8];
		FileOutputStream fos = null;
		FileInputStream encryptedFileStream = null;
		FileInputStream signatureFileStream = null;
		CipherInputStream inputStream = null;

		try {
			fos = new FileOutputStream(outputFile);
			encryptedFileStream = new FileInputStream(params.encFile);
			inputStream = new CipherInputStream(encryptedFileStream, AESCipher);

			int bytesRead;
			while ((bytesRead = inputStream.read(buffer)) != -1) {
				fos.write(buffer, 0, bytesRead);
			}
			signatureFileStream = new FileInputStream(outputFile);
			bytesRead = 0;
			byte[] readBuffer = new byte[8];
			while ((bytesRead = signatureFileStream.read(readBuffer)) != -1) {
				signature.update(readBuffer, 0, bytesRead);
			}

			if (!signature.verify(params.signResult)) {
				throw new Exception("The signatures do not match.");
			}
		} finally {
			inputStream.close();
			encryptedFileStream.close();
			fos.close();
			signatureFileStream.close();
		}
	}
}
