import java.io.IOException;
import java.security.GeneralSecurityException;

public class Crypto {

	public static final String KEYSTORE_FILENAME = "crypto.ks";

	/**
	 * Crypto file encryptor/decryptor.
	 * 
	 * Usage:
	 *   Crypto encrypt <keypass> <filename>
	 *     Encrypts file using 'encryptor' key in keystore.
	 *     Output is 2 files: Encrypted copy of the file,
	 *     and an encryption configuration file.
	 *     Password to keystore must be provided.
	 * Crypto decrypt <keypass> <encrypted_file>
	 * 	   Decrypts file using 'decryptor' key in keystore.
	 * 	   Password to keystore must be provided.
	 */
	public static void main(String[] args) {
		if (args.length >= 1) {
			String cmd = args[0];

			if (cmd.equals("encrypt")) {
				if (args.length == 3) {
					try {
						Encryptor encryptor = new Encryptor(args[1]);
						String encrypted = encryptor.encryptFile(args[2]);

						System.out.println("Done!");
						System.out.println("Encrypted file is " + encrypted);
						System.out.println("Config file is "
								+ EncryptionParams.configFilename(args[2]));
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
						Decryptor decryptor = new Decryptor(args[1], args[2]);
						String decrypted = decryptor.decryptFile(args[2]);

						System.out.println("Done!");
						System.out.println("Decrypted file is " + decrypted);
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

		// no match?
		printUsage();
	}

	public static void printUsage() {
		System.err.println("Usage:");
		System.err.println("  Crypto encrypt <keypass> <filename>");
		System.err.println("    Encrypts file using 'encryptor' key "
				+ "in keystore.");
		System.err.println("    Output is 2 files: Encrypted copy of"
				+ "the file, and an encryption configuration file.");
		System.err.println("    Password to keystore must be provided.");
		System.err.println("  Crypto decrypt <keypass> <encrypted_file>");
		System.err.println("    Decrypts file using 'decryptor' key "
				+ "in keystore.");
		System.err.println("    Password to keystore must be provided.");
	}

}
