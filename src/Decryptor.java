import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
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

	private Cipher secretCipher;
	private Signature signature;

	private EncryptionParams params;

	public Decryptor(String keypass, String originalFile) throws IOException, GeneralSecurityException {
		// load params from config file
		try {
			this.params = EncryptionParams.readFromFile(originalFile);
		} catch (ClassNotFoundException e) {
			throw new IOException("Corrupted config file.");
		}
		
		// load keys from keystore
		KeyStore keyStore = KeyStore.getInstance(params.keyStoreType,
				params.keyStoreProvider);
		FileInputStream inputStream = new FileInputStream(
				Crypto.KEYSTORE_FILENAME);
		keyStore.load(inputStream, keypass.toCharArray());
		PrivateKey encryptorPrivateKey = (PrivateKey) keyStore.getKey(
				params.encryptorKeyName, params.encryptorKeyPass.toCharArray());
		Cipher encryptorCipher = Cipher.getInstance(params.encryptorAlgorithm,
				params.encryptorCryptProvider);
		encryptorCipher.init(Cipher.DECRYPT_MODE, encryptorPrivateKey);
		encryptorCipher.update(params.encryptedKey);

		// load signature
		signature = Signature.getInstance(params.sigAlgorithm,
				params.sigCryptProvider);
		PublicKey signaturePublicKey = keyStore.getCertificate(
				params.sigKeyName).getPublicKey();
		signature.initVerify(signaturePublicKey);
		
		// prepare secret key cipher
		secretCipher = Cipher.getInstance(params.secretAlgorithm,
				params.secretCryptProvider);
		byte[] secretKeyBytes = encryptorCipher.doFinal();
		SecretKey secretKey = new SecretKeySpec(secretKeyBytes,
				params.keyGenAlgorithm);
		secretCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(
				params.iv));
	}

	public String decryptFile(String filename) throws IOException, GeneralSecurityException {
		String outputFile = filename + ".dec";

		byte[] buffer = new byte[8];
		FileOutputStream fos = null;
		FileInputStream encryptedFileStream = null;
		FileInputStream signatureFileStream = null;
		CipherInputStream inputStream = null;

		try {
			fos = new FileOutputStream(outputFile);
			encryptedFileStream = new FileInputStream(params.encryptedFile);
			inputStream = new CipherInputStream(encryptedFileStream, secretCipher);

			// iteratively write decrypted data to file
			int bytesRead;
			while ((bytesRead = inputStream.read(buffer)) != -1) {
				fos.write(buffer, 0, bytesRead);
			}

			// verify signature with one from config object
			signatureFileStream = new FileInputStream(outputFile);
			bytesRead = 0;
			byte[] readBuffer = new byte[8];
			while ((bytesRead = signatureFileStream.read(readBuffer)) != -1) {
				signature.update(readBuffer, 0, bytesRead);
			}
			if (!signature.verify(params.signature)) {
				throw new GeneralSecurityException("Signatures do not match.");
			}
		} finally {
			inputStream.close();
			encryptedFileStream.close();
			fos.close();
			signatureFileStream.close();
		}
		
		return outputFile;
	}

}
