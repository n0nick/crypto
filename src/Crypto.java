
public class Crypto {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if (args.length >= 1) {
			String cmd = args[0];
			
			if (cmd.equals("encrypt")) {
				if (args.length == 3) {
					System.out.println("Ecnryptinizor!");
					return;
				}
			} else if (cmd.equals("decrypt")) {
				if (args.length == 4) {
					System.out.println("Decryptinizor!");
					return;
				}
			}
		}
		
		// no match
		printUsage();
	}
	
	public static void printUsage() {
		System.out.println("Usage:");
		System.out.println("  Crypto encrypt <filename> <keypass>");
		System.out.println("    Encrypts file using 'encryptor' key in keystore.");
		System.out.println("    Output is 2 files: Encrypted copy of the file, " +
				"and an encryption configuration file.");
		System.out.println("    Password to keystore must be provided.");
		System.out.println("  Crypto decript <encrypted_file> <encryption_cfg> <keypass>");
		System.out.println("    Decrypts file using 'decryptor' key in keystore.");
		System.out.println("    Password to keystore must be provided.");
	}

}
