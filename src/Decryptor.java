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
	private Cipher RSACipher;
	private Signature signature;
	private SecretKey AESKey;
	private String RSAToken;
	private String DSAToken;
	private String AESType;
	private String RSAType;
	private KeyStore keyStore;
	private PrivateKey RSAPrivateKey;
	private PublicKey DSAPublicKey;
	private String configFile;
	private String AESProvider;
	private String RSAProvider;
	private String DSAProvider;
	private byte[] signatureResult;
	private String encryptedFile;
	private String keystoreFile;
	private String DSAType;
	private String keyStoreType;
	private String RSAPassword;
	private byte[] encryptedKey;
	private String keyGenType;
	private byte[] IV;
	private String keyStoreProvider;

	public Decryptor(String keypass) throws Exception {
		
		// init all the local variables
		configFile = "config.txt";
		readConfigFromFile();
		
		keystoreFile = Crypto.KEYSTORE_FILENAME;
		
		AESCipher = Cipher.getInstance(AESType, AESProvider);
		RSACipher = Cipher.getInstance(RSAType, RSAProvider);
		signature = Signature.getInstance(DSAType, DSAProvider);
		keyStore = KeyStore.getInstance(keyStoreType,
				keyStoreProvider);
		FileInputStream inputStream = new FileInputStream(keystoreFile);
		keyStore.load(inputStream, keypass.toCharArray());
		RSAPrivateKey = (PrivateKey) keyStore.getKey(RSAToken,
				RSAPassword.toCharArray());
		DSAPublicKey = keyStore.getCertificate(DSAToken).getPublicKey();
		RSACipher.init(Cipher.DECRYPT_MODE, RSAPrivateKey);
		signature.initVerify(DSAPublicKey);
		RSACipher.update(encryptedKey);
		byte[] temp = RSACipher.doFinal();
		AESKey = new SecretKeySpec(temp, keyGenType);
		AESCipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV));
	}

	private void readConfigFromFile() throws Exception {
		EncryptionParams params = EncryptionParams.readFromFile(configFile);
		this.DSAToken = params.decryptorKeyName;
		this.RSAToken = params.encryptorKeyName;
		this.RSAPassword = params.encryptorKeyPass;
		this.encryptedKey = params.encryptedKey;
		this.encryptedFile = params.encFile;
		this.IV = params.initVec;
		this.keyGenType = params.keyGenType;
		this.signatureResult = params.signResult;
		this.AESProvider = params.AES_CRYPT_PROVIDER;
		this.DSAProvider = params.DSA_CRYPT_PROVIDER;
		this.RSAProvider  = params.RSA_CRYPT_PROVIDER;
		this.keyStoreProvider = params.ksProvider;
		this.AESType = params.AES_ALGORITHM_TYPE;
		this.RSAType = params.RSA_ALGORITHM_TYPE;
		this.DSAType = params.DSA_ALGORITHM_TYPE;
		this.keyStoreType  = params.ksType;
	}

	public void doWork(String outputFile) throws Exception {

		//this.readConfigFromFile();
		byte[] buffer = new byte[8];
		FileOutputStream fos = null;
		FileInputStream encryptedFileStream = null;
		FileInputStream signatureFileStream = null;
		CipherInputStream inputStream = null;

		try {
			fos = new FileOutputStream(outputFile);
			encryptedFileStream = new FileInputStream(this.encryptedFile);
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

			if (!signature.verify(signatureResult)) {
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
