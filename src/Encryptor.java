import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryptor {

	private Signature signature;

	private Cipher secretCipher;
	private SecretKey secretKey;

	private EncryptionParams params;

	public Encryptor(String keypass) throws IOException,
			GeneralSecurityException {

		// initiate config object, with my algorithm/provider choices
		this.params = new EncryptionParams();

		// keystore file properties
		params.keyStoreType = "JCEKS";
		params.keyStoreProvider = "SunJCE";

		// algorithm choices
		params.keyGenAlgorithm = "AES";
		params.secretAlgorithm = "AES/CBC/PKCS5Padding";
		params.sigAlgorithm = "DSA";
		params.encryptorAlgorithm = "RSA";

		// crypt provider choices
		params.secretCryptProvider = "SunJCE";
		params.encryptorCryptProvider = "SunJCE";
		params.sigCryptProvider = "SUN";

		// encryptor key in keystore
		params.encryptorKeyName = "encryptor";
		params.encryptorKeyPass = "DJc8k7W9";

		// decryptor key in keystore
		params.sigKeyName = "decryptor";
		String decryptorKeyPass = "w043Ea-H"; // not saved to config file

		// prepare secret key, cipher (for randomizing encryption key)
		KeyGenerator keyGen = KeyGenerator.getInstance(params.keyGenAlgorithm);
		SecureRandom secRandom = new SecureRandom();
		secRandom.nextBytes(params.iv);
		secretCipher = Cipher.getInstance(params.secretAlgorithm);
		secretKey = keyGen.generateKey();
		secretCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(
				params.iv));

		// prepare keys from keystore
		KeyStore ks = KeyStore.getInstance(params.keyStoreType);
		FileInputStream inputStream = new FileInputStream(
				Crypto.KEYSTORE_FILENAME);
		ks.load(inputStream, keypass.toCharArray());
		PrivateKey sigPrivateKey = (PrivateKey) ks.getKey(params.sigKeyName,
				decryptorKeyPass.toCharArray());
		Certificate encryptorCertificate = ks
				.getCertificate(params.encryptorKeyName);
		Cipher encryptorCipher = Cipher.getInstance(params.encryptorAlgorithm);
		encryptorCipher.init(Cipher.ENCRYPT_MODE, encryptorCertificate);
		encryptorCipher.update(secretKey.getEncoded());
		params.encryptedKey = encryptorCipher.doFinal();

		// prepare signature
		signature = Signature.getInstance(params.sigAlgorithm);
		signature.initSign(sigPrivateKey);
	}

	public String encryptFile(String filename) throws IOException,
			GeneralSecurityException {

		params.encryptedFile = filename + ".enc";

		FileInputStream fileInput = null;
		FileOutputStream fileOutput = null;
		CipherOutputStream outputStream = null;

		try {
			int bytesRead;
			byte[] readBuffer = new byte[8];
			fileInput = new FileInputStream(filename);
			fileOutput = new FileOutputStream(params.encryptedFile);
			outputStream = new CipherOutputStream(fileOutput, secretCipher);

			// iteratively write encrypted data to file and update signature
			while ((bytesRead = fileInput.read(readBuffer)) != -1) {
				outputStream.write(readBuffer, 0, bytesRead);
				this.signature.update(readBuffer, 0, bytesRead);
			}

			// complete signature
			params.signature = this.signature.sign();

			// save config file
			params.writeToFile(filename);
		} finally {
			outputStream.close();
			fileInput.close();
			fileOutput.flush();
			fileOutput.close();
		}

		return params.encryptedFile;
	}
}
