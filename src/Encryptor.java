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

	public Encryptor(String keypass) throws IOException, GeneralSecurityException {

		this.params = new EncryptionParams();

		params.keyGenAlgorithm = "AES";

		params.keyStoreType = "JCEKS";
		params.keyStoreProvider = "SunJCE";

		params.secretAlgorithm = "AES/CBC/PKCS5Padding";
		params.sigAlgorithm = "DSA";
		params.encryptorAlgorithm = "RSA";

		params.secretCryptProvider = "SunJCE";
		params.encryptorCryptProvider = "SunJCE";
		params.sigCryptProvider = "SUN";

		params.encryptorKeyName = "encryptor";
		params.encryptorKeyPass = "DJc8k7W9";

		params.sigKeyName = "decryptor";
		String decryptorKeyPass = "w043Ea-H";

		signature = Signature.getInstance(params.sigAlgorithm);
		KeyGenerator keyGen = KeyGenerator
				.getInstance(params.keyGenAlgorithm);
		SecureRandom secRandom = new SecureRandom();
		secRandom.nextBytes(params.iv);
		secretCipher = Cipher.getInstance(params.secretAlgorithm);
		secretKey = keyGen.generateKey();
		
		Cipher encryptorCipher = Cipher
				.getInstance(params.encryptorAlgorithm);
		
		KeyStore ks = KeyStore.getInstance(params.keyStoreType);
		FileInputStream inputStream = new FileInputStream(
				Crypto.KEYSTORE_FILENAME);
		ks.load(inputStream, keypass.toCharArray());
		PrivateKey sigPrivateKey = (PrivateKey) ks.getKey(
				params.sigKeyName, decryptorKeyPass.toCharArray());
		Certificate encryptorCertificate = ks
				.getCertificate(params.encryptorKeyName);

		secretCipher.init(Cipher.ENCRYPT_MODE, secretKey,
				new IvParameterSpec(params.iv));

		encryptorCipher.init(Cipher.ENCRYPT_MODE, encryptorCertificate);
		signature.initSign(sigPrivateKey);
		encryptorCipher.update(secretKey.getEncoded());
		params.encryptedKey = encryptorCipher.doFinal();

	}

	public void encryptFile(String filename) throws IOException, GeneralSecurityException {

		params.encryptedFile = filename + ".enc";

		FileInputStream fileInput = null;
		FileOutputStream fileOutput = null;
		CipherOutputStream outputStream = null;
		
		try {
			byte[] readBuffer = new byte[8];
			int bytesRead;
			fileInput = new FileInputStream(filename);
			fileOutput = new FileOutputStream(filename + ".enc");

			outputStream = new CipherOutputStream(fileOutput, secretCipher);

			while ((bytesRead = fileInput.read(readBuffer)) != -1) {
				outputStream.write(readBuffer, 0, bytesRead);
				this.signature.update(readBuffer, 0, bytesRead);
			}

			params.signature = this.signature.sign();

			params.writeToFile(filename + ".cfg");
		} finally {
			outputStream.close();
			fileInput.close();
			fileOutput.flush();
			fileOutput.close();
		}
	}
}
