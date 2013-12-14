import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class EncryptionParams implements java.io.Serializable {

	private static final long serialVersionUID = 7014557932766694444L;

	public String encryptorKeyName;
	public String encryptorKeyPass;
	public String encryptorCryptProvider;
	public String encryptorAlgorithm;

	public String sigKeyName;
	public String sigAlgorithm;
	public String sigCryptProvider;

	public String secretAlgorithm;
	public String secretCryptProvider;

	public String keyStoreProvider;
	public String keyStoreType;

	public String keyGenAlgorithm;
	public byte[] encryptedKey;
	public String encryptedFile; // encrypted filename
	public byte[] iv = new byte[16]; // cipher initialization vector
	public byte[] signature;

	public void writeToFile(String originalFile) throws IOException {
		FileOutputStream fout = new FileOutputStream(
				configFilename(originalFile));
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(this);
		oos.close();
	}

	public static EncryptionParams readFromFile(String originalFile)
			throws IOException, ClassNotFoundException {
		FileInputStream fin = new FileInputStream(configFilename(originalFile));
		ObjectInputStream ois = new ObjectInputStream(fin);
		EncryptionParams params = (EncryptionParams) ois.readObject();
		ois.close();
		return params;
	}

	public static String configFilename(String originalFile) {
		return originalFile + ".cfg";
	}

}
