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
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryptor {
	public void encryptFile(String filename) throws Exception {
		this.doWork(filename);
		this.prepareConfigFile();
	}

	private Signature signature;
	private SecureRandom secRandom;
	private byte[] signResult;
	private String encFile;
	private String confFile;
	private String signFile;
	private byte[] initVec = new byte[16];
	private String keyGenType;
	private byte[] encryptedKey;
	private Cipher decode;

	// DSA vars
	private String DSA_CRYPT_PROVIDER;
	private String decryptorKeyName;
	private String DSA_ALGORITHM_TYPE;
	private String decryptorKeyPass;

	// AES vars
	private Cipher cipherAES;
	private KeyGenerator genAES;
	private String AES_ALGORITHM_TYPE;
	private String AES_CRYPT_PROVIDER;
	private SecretKey AESSecKey;

	// RSA vars
	private Cipher cipherRSA;
	private Certificate RSACertificate;
	private String RSA_CRYPT_PROVIDER;
	private String RSA_ALGORITHM_TYPE;
	private String encryptorKeyName;
	private String encryptorKeyPass;
	private PrivateKey DSAPrivateKey;

	// keystore vars
	private KeyStore ks;
	private String ksProvider;
	private String ksType;
	private String ksPass;
	private String ksFile;

	public Encryptor(String keypass) {

		// constructor for initializing all the vars
		try {
			this.keyGenType = "AES";
			
			this.ksType = "JCEKS";
			this.ksProvider = "SunJCE";
			
			this.AES_ALGORITHM_TYPE = "AES/CBC/PKCS5Padding";
			this.RSA_ALGORITHM_TYPE = "RSA";
			this.DSA_ALGORITHM_TYPE = "DSA";
			
			this.AES_CRYPT_PROVIDER = "SunJCE";
			this.RSA_CRYPT_PROVIDER = "SunJCE";
			this.DSA_CRYPT_PROVIDER = "SUN";
			this.confFile = "config.txt";
			this.encFile = "output.txt";
			this.signFile = "signature.txt";

			this.encryptorKeyName = "encryptor";
			this.encryptorKeyPass = "DJc8k7W9";
			
			this.decryptorKeyName = "decryptor";
			this.decryptorKeyPass = "w043Ea-H";
			
			this.ksFile = Crypto.KEYSTORE_FILENAME;
			this.ksPass = keypass;

			this.signature = Signature.getInstance("DSA");
			this.decode = Cipher.getInstance(AES_ALGORITHM_TYPE);
			this.genAES = KeyGenerator.getInstance("AES");
			this.secRandom = new SecureRandom();
			secRandom.nextBytes(initVec);
			this.cipherAES = Cipher.getInstance(AES_ALGORITHM_TYPE);
			this.cipherRSA = Cipher.getInstance("RSA");
			AESSecKey = genAES.generateKey();
			this.ks = KeyStore.getInstance(this.ksType);
			FileInputStream inputStream = new FileInputStream(ksFile);
			ks.load(inputStream, ksPass.toCharArray());
			this.DSAPrivateKey = (PrivateKey) ks.getKey(decryptorKeyName,
					decryptorKeyPass.toCharArray());
			this.RSACertificate = ks.getCertificate(encryptorKeyName);

			cipherAES.init(Cipher.ENCRYPT_MODE, AESSecKey, new IvParameterSpec(
					initVec));
			decode.init(Cipher.DECRYPT_MODE, AESSecKey, new IvParameterSpec(
					initVec));
			this.cipherRSA.init(Cipher.ENCRYPT_MODE, RSACertificate);
			this.signature.initSign(DSAPrivateKey);
			cipherRSA.update(AESSecKey.getEncoded());
			this.encryptedKey = cipherRSA.doFinal();
		} catch (Exception e) {
			System.out.println("Error initializing: " + e.getMessage());
		}

	}

	public void prepareConfigFile() throws IOException {
		BufferedWriter out = null;
		try {
			out = new BufferedWriter(new FileWriter(confFile));
			String newline = "\r\n";
			out.write(decryptorKeyName + newline);
			out.write(encryptorKeyName + newline);
			out.write(ksFile + newline);
			out.write(Arrays.toString(encryptedKey) + newline);
			out.write(encFile + newline);
			out.write(ksPass + newline);
			out.write(encryptorKeyPass + newline);
			out.write(Arrays.toString(initVec) + newline);
			out.write(keyGenType + newline);
			out.write(Integer.toString(encryptedKey.length) + newline);
			out.write(Integer.toString(initVec.length) + newline);
			out.write(Integer.toString(signResult.length) + newline);
			out.write(Arrays.toString(signResult) + newline);
			out.write(AES_CRYPT_PROVIDER + newline);
			out.write(DSA_CRYPT_PROVIDER + newline);
			out.write(RSA_CRYPT_PROVIDER + newline);
			out.write(ksProvider + newline);
			out.write(AES_ALGORITHM_TYPE + newline);
			out.write(RSA_ALGORITHM_TYPE + newline);
			out.write(DSA_ALGORITHM_TYPE + newline);
			out.write(ksType + newline);
		} finally {
			out.close();
		}
	}

	public void doWork(String fileToEncrypt) throws Exception {

		this.encFile = fileToEncrypt + ".enc";
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
			this.signResult = this.signature.sign();
			out = new BufferedWriter(new FileWriter(signFile));
			out.write(Integer.toString(signResult.length) + "\r\n");
			out.write(Arrays.toString(signResult) + "\r\n");
		} finally {
			outputStream.close();
			fileInput.close();
			fileOutput.flush();
			fileOutput.close();
			out.close();
		}
	}
}
