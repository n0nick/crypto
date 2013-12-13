import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class EncryptionParams implements java.io.Serializable {

	private static final long serialVersionUID = 7014557932766694444L;
	
	private byte[] initVec = new byte[16];
	private String keyGenType;
	private byte[] encryptedKey;
		
	private String RSAToken;
	private String RSAPassword;

	private String ksProvider;
	private String ksType;
	private String ksFile;
	
	public byte[] signatureResult;
	
	public void setEncryptionParams() {
	   keyGenType = "AES";
	   ksType = "JCEKS";
	   ksProvider = "SunJCE";
	   RSAPassword = "shayrsa";
	   ksFile = "ShaysKeyStore.jks";   
 	}
	
	public void writeToFile(String fileName) throws IOException {
		FileOutputStream fout = new FileOutputStream(fileName);
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(this);
		oos.close();
	}
	
	public static EncryptionParams readFromFile(String fileName) throws IOException, ClassNotFoundException {
		FileInputStream fin = new FileInputStream(fileName);
		ObjectInputStream ois = new ObjectInputStream(fin);
		EncryptionParams params = (EncryptionParams) ois.readObject();
		ois.close();
		return params;
	}
	
}
