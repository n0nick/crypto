
public class Crypto {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if (args.length >= 1) {
			String cmd = args[0];
			
			if (cmd.equals("encrypt")) {
				if (args.length == 3) {
					Encryptor encryptor = new Encryptor(args[1]);
					encryptor.encryptFile(args[2]);
					return;
				}
			} else if (cmd.equals("decrypt")) {
				if (args.length == 4) {
					Decryptor decryptor = new Decryptor(args[1]);
					decryptor.decryptFile(args[2], args[3]);
					return;
				}
			}
		}
		
		// no match
		printUsage();
	}
	
	public static void printUsage() {
		System.out.println("Usage:");
		System.out.println("  Crypto encrypt <keypass> <filename>");
		System.out.println("    Encrypts file using 'encryptor' key in keystore.");
		System.out.println("    Output is 2 files: Encrypted copy of the file, " +
				"and an encryption configuration file.");
		System.out.println("    Password to keystore must be provided.");
		System.out.println("  Crypto decript <keypass> <encrypted_file> <encryption_cfg>");
		System.out.println("    Decrypts file using 'decryptor' key in keystore.");
		System.out.println("    Password to keystore must be provided.");
	}

}
