import java.io.IOException;
import java.security.GeneralSecurityException;

public class Crypto {
	
	public static final String KEYSTORE_FILENAME = "crypto.ks";

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if (args.length >= 1) {
			String cmd = args[0];
			
			if (cmd.equals("encrypt")) {
				if (args.length == 3) {
					try {
						Encryptor encryptor = new Encryptor(args[1]);
						encryptor.encryptFile(args[2]);
					} catch (GeneralSecurityException e) {
						System.err.println("Error while encrypting.");
						System.err.println(e.getMessage());
					} catch (IOException e) {
						System.err.println("Error accessing file to encrypt.");
						System.err.println(e.getMessage());
					}
					return;
				}
			} else if (cmd.equals("decrypt")) {
				if (args.length == 3) {
					try {
						String configFile = args[2] + ".cfg";
						Decryptor decryptor = new Decryptor(args[1], configFile);
						decryptor.decryptFile(args[2]);
					} catch (GeneralSecurityException e) {
						System.err.println("Error while decrypting.");
						System.err.println(e.getMessage());
					} catch (IOException e) {
						System.err.println("Error accessing file to decrypt.");
						System.err.println(e.getMessage());
					}
					return;
				}
			}
		}
		
		// no match
		printUsage();
	}
	
	public static void printUsage() {
		System.err.println("Usage:");
		System.err.println("  Crypto encrypt <keypass> <filename>");
		System.err.println("    Encrypts file using 'encryptor' key in keystore.");
		System.err.println("    Output is 2 files: Encrypted copy of the file, " +
				"and an encryption configuration file.");
		System.err.println("    Password to keystore must be provided.");
		System.err.println("  Crypto decript <keypass> <encrypted_file>");
		System.err.println("    Decrypts file using 'decryptor' key in keystore.");
		System.err.println("    Password to keystore must be provided.");
	}

}
