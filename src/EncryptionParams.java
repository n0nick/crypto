import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class EncryptionParams implements java.io.Serializable {

	private static final long serialVersionUID = 7014557932766694444L;

	// encryptor key, passwword, crypt provider, algorithm
	public String encryptorKeyName;
	public String encryptorKeyPass;
	public String encryptorCryptProvider;
	public String encryptorAlgorithm;
	public byte[] encryptedKey;

	// signature key, algorithm, crypt provider
	public String sigKeyName;
	public String sigAlgorithm;
	public String sigCryptProvider;

	// secret key algorithm, crypt provider
	public String secretAlgorithm;
	public String secretCryptProvider;
	public String keyGenAlgorithm;

	// keystore properties
	public String keyStoreProvider;
	public String keyStoreType;

	// file encryption data
	public byte[] iv = new byte[16]; // cipher initialization vector
	public String encryptedFile; // encrypted filename
	public byte[] signature; // signature data

	public void writeToFile(String originalFilename) throws IOException {
		FileOutputStream fout = new FileOutputStream(
				configFilename(originalFilename));
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(this);
		oos.close();
	}

	public static EncryptionParams readFromFile(String originalFilename)
			throws IOException, ClassNotFoundException {
		FileInputStream fin = new FileInputStream(
				configFilename(originalFilename));
		ObjectInputStream ois = new ObjectInputStream(fin);
		EncryptionParams params = (EncryptionParams) ois.readObject();
		ois.close();
		return params;
	}

	public static String configFilename(String originalFile) {
		return originalFile + ".cfg";
	}

}
