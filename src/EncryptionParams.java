import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class EncryptionParams implements java.io.Serializable {

	private static final long serialVersionUID = 7014557932766694444L;

	public String decryptorKeyName;
	public String encryptorKeyName;
	public byte[] encryptedKey;
	public String encFile;
	public String encryptorKeyPass;
	public byte[] initVec = new byte[16];
	public String keyGenType;
	public int encryptedKeyLength;
	public int initVecLength;
	public int signResultLength;
	public byte[] signResult;
	public String AES_CRYPT_PROVIDER;
	public String DSA_CRYPT_PROVIDER;
	public String RSA_CRYPT_PROVIDER;
	public String ksProvider;
	public String AES_ALGORITHM_TYPE;
	public String RSA_ALGORITHM_TYPE;
	public String DSA_ALGORITHM_TYPE;
	public String ksType;

	public void writeToFile(String fileName) throws IOException {
		FileOutputStream fout = new FileOutputStream(fileName);
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(this);
		oos.close();
	}

	public static EncryptionParams readFromFile(String fileName)
			throws IOException, ClassNotFoundException {
		FileInputStream fin = new FileInputStream(fileName);
		ObjectInputStream ois = new ObjectInputStream(fin);
		EncryptionParams params = (EncryptionParams) ois.readObject();
		ois.close();
		return params;
	}

}
