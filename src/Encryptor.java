import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryptor {

	private static final String CIPHER_AES_TYPE = "AES/CBC/PKCS5Padding";
	private static final String CIPHER_PROVIDER = "SunJCE";
	private static final String CIPHER_RSA_TYPE = "RSA";

	private static final String SIGNATURE_ALGORITHM = "DSA";
	private static final String SIGNATURE_PROVIDER = "SUN";

	private String keypass;

	private Cipher cipherAES, cipherRSA, decode;
	private KeyGenerator genAES;
	private KeyStore keystore;

	public Encryptor(String keypass) throws IOException {
		this.keypass = keypass;

		try {
			String keyGenType = "AES";
			String ksType = "JCEKS";
			String ksProvider = "SunJCE";

			String RSAPassword = "shayrsa";
			String DSAPassword = "shaydsa";

			this.decode = Cipher.getInstance(CIPHER_AES_TYPE, CIPHER_PROVIDER);

			this.cipherRSA = Cipher.getInstance(CIPHER_RSA_TYPE,
					CIPHER_PROVIDER);

			this.keystore = KeyStore.getInstance(ksType, ksProvider);
			FileInputStream inputStream = new FileInputStream(
					Crypto.KEYSTORE_FILENAME);
			keystore.load(inputStream, keypass.toCharArray());

			String DSAToken = "dsa";
			PrivateKey DSAPrivateKey = (PrivateKey) keystore.getKey(DSAToken,
					DSAPassword.toCharArray());
			String RSAToken = "rsa";
			Certificate RSACertificate = keystore.getCertificate(RSAToken);

			this.genAES = KeyGenerator.getInstance("AES");
			SecretKey AESSecKey = genAES.generateKey();

			byte[] initVec = new byte[16];
			SecureRandom secRandom = new SecureRandom();
			secRandom.nextBytes(initVec);

			this.cipherAES = Cipher.getInstance(CIPHER_AES_TYPE,
					CIPHER_PROVIDER);
			this.cipherAES.init(Cipher.ENCRYPT_MODE, AESSecKey,
					new IvParameterSpec(initVec));

			decode.init(Cipher.DECRYPT_MODE, AESSecKey, new IvParameterSpec(
					initVec));
			this.cipherRSA.init(Cipher.ENCRYPT_MODE, RSACertificate);

			cipherRSA.update(AESSecKey.getEncoded());

			byte[] encryptedKey = cipherRSA.doFinal();
		} catch (GeneralSecurityException e) {

		}
	}

	public void encryptFile(String filename) throws IOException {
		EncryptionParams params = new EncryptionParams();

		String encryptedFilename = filename + ".enc";

		FileInputStream fin = null;
		FileOutputStream fout = null;
		CipherOutputStream cos = null;

		try {
			byte[] readBuffer = new byte[8];
			int bytesRead;
			fin = new FileInputStream(filename);
			fout = new FileOutputStream(encryptedFilename);

			Cipher cipherAES = Cipher.getInstance(CIPHER_AES_TYPE,
					CIPHER_PROVIDER);
			cos = new CipherOutputStream(fout, cipherAES);

			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM,
					SIGNATURE_PROVIDER);
			PrivateKey DSAPrivateKey = (PrivateKey) keystore.getKey(DSAToken,
					DSAPassword.toCharArray());
			signature.initSign(DSAPrivateKey);

			byte[] signResult = signature.sign();

			while ((bytesRead = fin.read(readBuffer)) != -1) {
				cos.write(readBuffer, 0, bytesRead);
				signature.update(readBuffer, 0, bytesRead);
			}

			signResult = signature.sign();
			params.signatureResult = signResult;

		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} finally {
			cos.close();
			fin.close();
			fout.flush();
			fout.close();
		}
	}
}
