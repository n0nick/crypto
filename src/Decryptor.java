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

	private Cipher aesCipher;
	private Signature signature;

	private EncryptionParams params;

	public Decryptor(String keypass, String configFile) throws IOException, GeneralSecurityException {
		try {
			this.params = EncryptionParams.readFromFile(configFile);
		} catch (ClassNotFoundException e) {
			throw new IOException("Corrupted config file.");
		}

		aesCipher = Cipher.getInstance(params.secretAlgorithm,
				params.secretCryptProvider);
		Cipher rsaCipher = Cipher.getInstance(params.encryptorAlgorithm,
				params.encryptorCryptProvider);
		signature = Signature.getInstance(params.sigAlgorithm,
				params.sigCryptProvider);
		KeyStore keyStore = KeyStore.getInstance(params.keyStoreType,
				params.keyStoreProvider);
		FileInputStream inputStream = new FileInputStream(
				Crypto.KEYSTORE_FILENAME);
		keyStore.load(inputStream, keypass.toCharArray());
		PrivateKey rsaPrivateKey = (PrivateKey) keyStore.getKey(
				params.encryptorKeyName, params.encryptorKeyPass.toCharArray());
		PublicKey DSAPublicKey = keyStore.getCertificate(
				params.sigKeyName).getPublicKey();
		rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
		signature.initVerify(DSAPublicKey);
		rsaCipher.update(params.encryptedKey);
		byte[] aesKeyBytes = rsaCipher.doFinal();
		SecretKey aesKey = new SecretKeySpec(aesKeyBytes,
				params.keyGenAlgorithm);
		aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(
				params.iv));
	}

	public void decryptFile(String filename) throws IOException, GeneralSecurityException {
		String outputFile = filename + ".dec";

		byte[] buffer = new byte[8];
		FileOutputStream fos = null;
		FileInputStream encryptedFileStream = null;
		FileInputStream signatureFileStream = null;
		CipherInputStream inputStream = null;

		try {
			fos = new FileOutputStream(outputFile);
			encryptedFileStream = new FileInputStream(params.encryptedFile);
			inputStream = new CipherInputStream(encryptedFileStream, aesCipher);

			int bytesRead;
			while ((bytesRead = inputStream.read(buffer)) != -1) {
				fos.write(buffer, 0, bytesRead);
			}

			// verify signature
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
	}

}
