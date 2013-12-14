Crypto file encrypter/decrypter
===============================

A simple software utility for encrypting and decrypting files using the Java Crypto API.
Written as a software project for 0368-3066 Building Secure Applications (Tel Aviv University, Dec 2013).

Implementation details:
-----------------------

The project consists of four files: A main executable, an encryptor class, a decryptor class, and a params class for handling loading and saving a specific encryption's parameters into a configuration file.

The algorithm and crypt provider decisions are all collected in the Encryptor class constructor source (`Encryptor.java`). Changing the values of the different parameters would affect the encryption process. These parameters are stored into the configuration file that's attached to the encrypted file, and so the Decryptor class would use the values from that file.

To maintain compatibility and cross-platform support, Sun's providers were chosen accross the board for all crypts (either `SUN` or `SunJCE`).

As for algorithms, I made sure to select the algorithms that seemed most standard and secure in my research.
I've chosen AES as the algorithm for the secret key generation and the generation of its password.
I use RSA for the encryptor key, as it is the standard algorithm for encrypting data using a private key.
Lastly, the DSA algorithm is used for the decryptor key, which is used for the signature calculated on the file (and verified by the decryptor). DSA was developed especially for signing data and verifying signatures.

Usage:
------

    Crypto encrypt <keypass> <filename>
        Encrypts file using 'encryptor' key in keystore.
        Output is 2 files: Encrypted copy of the file,
        and an encryption configuration file.
        Password to keystore must be provided.
    Crypto decrypt <keypass> <encrypted_file>
        Decrypts file using 'decryptor' key in keystore.
        Password to keystore must be provided.

The program assumes a `crypto.ks` keystore is available under the current directory.

The decrypt command assumes a `{filename}.cfg` configuration file is available under the current directory (this file is generated along the encrypted file by the encrypt command).

Example:
--------
A keystore file `crypto.ks` was initiated using the commands:

    $ keytool -genkeypair -alias encryptor -keystore crypto.ks -keypass DJc8k7W9 -storepass pDut6LNA -dname "CN=Sagie Maoz, OU=Computer Science, O=Tel Aviv University, L=Tel Aviv, S=, C=Israel" -keyalg RSA

    $ keytool -genkeypair -alias decryptor -keystore crypto.ks -keypass w043Ea-H -storepass pDut6LNA -dname "CN=Sagie Maoz, OU=Computer Science, O=Tel Aviv University, L=Tel Aviv, S=, C=Israel" -keyalg DSA

An input file `input.txt` was created:

    $ cat input.txt
    Carmen Sandiego's location:
    -21.195872, 55.696728

Encrypting the file:

    $ java Crypto pDut6LNA input.txt
    Done!
    Encrypted file is input.txt.enc
    Config file is input.txt.cfg

The new files `input.txt.enc` and `input.txt.cfg` represent the encrypted file.

Decrypting the file (on a directory with those 2 files):

    $ java Crypto pDut6LNA input.txt
    Done!
    Decrypted file is input.txt.dec

    $ cat input.txt.dec
    Carmen Sandiego's location:
    -21.195872, 55.696728

Success! The two files' content is the same:

    $ diff input.txt input.txt.dec
    $
