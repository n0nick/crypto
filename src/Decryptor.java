import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
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

	private String keypass;

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
	private int signatureSize;
	private byte[] signatureResult;
	private String encryptedFile;
	private String keystoreFile;
	private String DSAType;
	private String keyStoreType;
	private String keyStorePassword;
	private String RSAPassword;
	private byte[] encryptedKey;
	private String keyGenType;
	private byte[] IV;
	private String keyStoreProvider;
	private int IVByteSize;
	private int encryptedKeyByteSize;

	public Decryptor(String keypass) throws Exception {
		
		// init all the local variables
		this.configFile = "config.txt";
		readConfigFromFile();
		

		this.keypass = keypass;
		this.keystoreFile = Crypto.KEYSTORE_FILENAME;
		
		this.AESCipher = Cipher.getInstance(this.AESType, this.AESProvider);
		this.RSACipher = Cipher.getInstance(this.RSAType, this.RSAProvider);
		this.signature = Signature.getInstance(this.DSAType, this.DSAProvider);
		this.keyStore = KeyStore.getInstance(this.keyStoreType,
				this.keyStoreProvider);
		FileInputStream inputStream = new FileInputStream(this.keystoreFile);
		keyStore.load(inputStream, this.keypass.toCharArray());
		this.RSAPrivateKey = (PrivateKey) keyStore.getKey(RSAToken,
				RSAPassword.toCharArray());
		this.DSAPublicKey = keyStore.getCertificate(DSAToken).getPublicKey();
		this.RSACipher.init(Cipher.DECRYPT_MODE, RSAPrivateKey);
		this.signature.initVerify(DSAPublicKey);
		RSACipher.update(this.encryptedKey);
		byte[] temp = RSACipher.doFinal();
		this.AESKey = new SecretKeySpec(temp, this.keyGenType);
		AESCipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV));
	}

	private void readConfigFromFile() throws Exception {
		BufferedReader in = null;
		try {
			in = new BufferedReader(new FileReader(configFile));
			this.DSAToken = in.readLine();
			this.RSAToken = in.readLine();
			this.keystoreFile = in.readLine(); //
			String tempKey = in.readLine();
			this.encryptedFile = in.readLine();
			this.keyStorePassword = in.readLine(); //
			this.RSAPassword = in.readLine();
			String tempIV = in.readLine();
			this.keyGenType = in.readLine();
			this.encryptedKeyByteSize = Integer.parseInt(in.readLine());
			this.IVByteSize = Integer.parseInt(in.readLine());
			this.encryptedKey = toByteArray(tempKey, encryptedKeyByteSize);
			this.IV = toByteArray(tempIV, IVByteSize);
			this.signatureSize = Integer.parseInt(in.readLine());
			String tempSig = in.readLine();
			this.signatureResult = toByteArray(tempSig, signatureSize);
			this.AESProvider = in.readLine();
			this.DSAProvider = in.readLine();
			this.RSAProvider = in.readLine();
			this.keyStoreProvider = in.readLine();
			this.AESType = in.readLine();
			this.RSAType = in.readLine();
			this.DSAType = in.readLine();
			this.keyStoreType = in.readLine();

		} finally {
			in.close();
		}
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

	private static byte[] toByteArray(String source, int byteSize) {
		String[] convertion = source.replaceAll("[\\[\\]]", "").split(", ");
		byte[] currentParam = new byte[byteSize];
		for (int i = 0; i < convertion.length; i++) {
			currentParam[i] = (byte) Integer.parseInt(convertion[i]);
		}
		return currentParam;
	}
}
