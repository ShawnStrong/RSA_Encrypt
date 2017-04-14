import java.math.BigInteger;
import java.util.*;
import java.io.*;
import java.sql.*;

/**
 * Class for RSA Algorithm (RSA.java).
 *
 * Generates Prime numbers and Public/Private Keys. Performs Encryption and
 * Decryption.
 *
 * @author Chue Wai Lian
 * @version
 *
 * 			1.0.0 11 Apr 2001 <br>
 *          1st release.
 */
public class RSA {
	/**
	 * Bit length of each prime number.
	 */
	int primeSize;

	/**
	 * Two distinct large prime numbers p and q.
	 */
	BigInteger p, q;

	/**
	 * Modulus N.
	 */
	BigInteger N;

	/**
	 * r = ( p - 1 ) * ( q - 1 )
	 */
	BigInteger r;

	/**
	 * Public exponent E and Private exponent D
	 */
	BigInteger E, D;
	static PrintStream pr;
	static FileOutputStream out;

	public RSA() throws Exception {

		out = new FileOutputStream("src/message.txt", true);
		pr = new PrintStream(out);
	}

	/**
	 * Constructor.
	 *
	 * @param primeSize
	 *            Bit length of each prime number.
	 */
	public RSA(int primeSize) throws Exception {
		out = new FileOutputStream("src/message.txt", true);
		pr = new PrintStream(out);
		this.primeSize = primeSize;
		System.out.println("primesize is : " + this.primeSize);
		// Generate two distinct large prime numbers p and q.
		long starttime = getCurrentTime();
		generatePrimeNumbers();

		// Generate Public and Private Keys.

		generatePublicPrivateKeys();
		long endtime = getCurrentTime();
		System.out.println("Total time taken for key generation is  " + (endtime - starttime));
		pr.println("Time taken for key generation of " + primeSize + " bit key is :" + (endtime - starttime));

	}

	public RSA(int primeSize, int probability) {

		this.primeSize = primeSize;
		System.out.println("primesize is : " + this.primeSize);
		long starttime = getCurrentTime();
		generatePrimeNumbers(probability);
		generatePublicPrivateKeys();
		long endtime = getCurrentTime();
		System.out.println("Total time taken for key generation is  " + (endtime - starttime));
		pr.println("Time taken for key generation of " + primeSize + " bit key is :" + (endtime - starttime));

	}

	/**
	 * Generate two distinct large prime numbers p and q.
	 */
	public void generatePrimeNumbers() {
		// System.out.println

		p = new BigInteger(primeSize, 10, new Random());

		do {
			q = new BigInteger(primeSize, 10, new Random());
		} while (q.compareTo(p) == 0);

	}

	public void generatePrimeNumbers(int probability) {
		// System.out.println

		p = new BigInteger(primeSize, probability, new Random());

		do {
			q = new BigInteger(primeSize, probability, new Random());
		} while (q.compareTo(p) == 0);

	}

	public long getCurrentTime() {
		java.util.Date date = Calendar.getInstance().getTime();
		Timestamp a = new Timestamp(date.getTime());
		long currentTime = Calendar.getInstance().getTimeInMillis();
		System.out.println("Time: " + currentTime);

		return currentTime;
	}

	/**
	 * Generate Public and Private Keys.
	 */
	public void generatePublicPrivateKeys() {
		// N = p * q
		N = p.multiply(q);

		// r = ( p - 1 ) * ( q - 1 )
		r = p.subtract(BigInteger.valueOf(1));
		r = r.multiply(q.subtract(BigInteger.valueOf(1)));

		// Choose E, coprime to and less than r
		do {
			E = new BigInteger(2 * primeSize, new Random());
		} while ((E.compareTo(r) != -1) || (E.gcd(r).compareTo(BigInteger.valueOf(1)) != 0));

		// Compute D, the inverse of E mod r
		D = E.modInverse(r);
	}

	/**
	 * Encrypts the plaintext (Using Public Key).
	 *
	 * @param message
	 *            String containing the plaintext message to be encrypted.
	 * @return The ciphertext as a BigInteger array.
	 */
	public BigInteger[] encrypt(String message, int blocksize) {
		long startencrypt = getCurrentTime();
		int i;
		byte[] temp = new byte[blocksize];

		byte[] digits = message.getBytes();
		int digitLength = digits.length;
		int add = digits.length % blocksize == 0 ? 0 : 1;

		BigInteger[] bigdigits = new BigInteger[digits.length / blocksize + add];
		int x = 0;
		for (i = 0; i < digitLength; i += blocksize) {
			for (int j = 0; j < blocksize && (i + j) < digitLength; j++) {
				temp[j] = digits[i + j];
			}
			bigdigits[x] = new BigInteger(temp);
			x++;
		}

		BigInteger[] encrypted = new BigInteger[bigdigits.length];

		for (i = 0; i < bigdigits.length; i++)
			encrypted[i] = bigdigits[i].modPow(E, N);
		long endencrypt = getCurrentTime();
		System.out.println("Total time taken for encryption is  " + (endencrypt - startencrypt));
		pr.println(
				"Time taken for key encryption when key size is  " + primeSize + " is :" + (endencrypt - startencrypt));
		return (encrypted);
	}

	/**
	 * Decrypts the ciphertext (Using Private Key).
	 *
	 * @param encrypted
	 *            BigInteger array containing the ciphertext to be decrypted.
	 * @return The decrypted plaintext.
	 */
	public String decrypt(BigInteger[] encrypted) {
		long startdecrypt = getCurrentTime();
		int i;

		BigInteger[] decrypted = new BigInteger[encrypted.length];

		for (i = 0; i < decrypted.length; i++)
			decrypted[i] = encrypted[i].modPow(D, N);

		// char[] charArray = new char[decrypted.length] ;
		String decryptText = "";
		for (i = 0; i < decrypted.length; i++) {
			byte[] temp = decrypted[i].toByteArray();
			decryptText += new String(temp);
		}

		/*
		 * for( i = 0 ; i < charArray.length ; i++ ) charArray[i] = (char) (
		 * decrypted[i].intValue() ) ; long enddecrypt=getCurrentTime();
		 * System.out.println("Total time taken for decryption is  "+(enddecrypt
		 * -startdecrypt));
		 * 
		 * return( new String( charArray ) ) ;
		 */
		long enddecrypt = getCurrentTime();
		System.out.println("Total time taken for decryption is  " + (enddecrypt - startdecrypt));
		pr.println(
				"Time taken for key decryption when key size is  " + primeSize + " is :" + (enddecrypt - startdecrypt));
		return (decryptText);
	}

	/**
	 * Get prime number p.
	 *
	 * @return Prime number p.
	 */
	public BigInteger getp() {
		return (p);
	}

	/**
	 * Get prime number q.
	 *
	 * @return Prime number q.
	 */
	public BigInteger getq() {
		return (q);
	}

	/**
	 * Get r.
	 *
	 * @return r.
	 */
	public BigInteger getr() {
		return (r);
	}

	/**
	 * Get modulus N.
	 *
	 * @return Modulus N.
	 */
	public BigInteger getN() {
		return (N);
	}

	/**
	 * Get Public exponent E.
	 *
	 * @return Public exponent E.
	 */
	public BigInteger getE() {
		return (E);
	}

	/**
	 * Get Private exponent D.
	 *
	 * @return Private exponent D.
	 */
	public BigInteger getD() {
		return (D);
	}

	/**
	 * RSA Main program for Unit Testing.
	 */
	public static void main(String[] args) throws Exception {
		new RSA();
		RSA.pr.println("The Statistics after execution of RSA algorithm");
		RSA.pr.println("");
		RSA.pr.println("---------------------------------------------------------------------------");
		int keysize[] = { 128, 256, 512, 768, 1024 };
		// Get bit length of each prime number
		for (int k = 0; k < keysize.length; k++) {
			int primeSize = keysize[k];
			int blocksize = primeSize / 8;

			// Generate Public and Private Keys

			RSA rsa = new RSA(primeSize);
			RSA.pr.println("");
			System.out.println("Key Size: [" + primeSize + "]");
			System.out.println("");

			System.out.println("Generated prime numbers p and q");
			System.out.println("p: [" + rsa.getp().toString(16).toUpperCase() + "]");
			System.out.println("q: [" + rsa.getq().toString(16).toUpperCase() + "]");
			System.out.println("");

			System.out.println("The public key is the pair (N, E) which will be published.");
			System.out.println("N: [" + rsa.getN().toString(16).toUpperCase() + "]");
			System.out.println("E: [" + rsa.getE().toString(16).toUpperCase() + "]");
			System.out.println("");

			System.out.println("The private key is the pair (N, D) which will be kept private.");
			System.out.println("N: [" + rsa.getN().toString(16).toUpperCase() + "]");
			System.out.println("D: [" + rsa.getD().toString(16).toUpperCase() + "]");
			System.out.println("");

			// Get message (plaintext) from user
			System.out.println("Please enter message (plaintext):");

			// String plaintext = ( new BufferedReader( new InputStreamReader(
			// System.in ) ) ).readLine() ;
			String plaintext = "This is the RSA algorithm";
			System.out.println(plaintext);

			// Encrypt Message
			RSA.pr.println("");
			BigInteger[] ciphertext = rsa.encrypt(plaintext, blocksize);

			System.out.print("Ciphertext: [");
			for (int i = 0; i < ciphertext.length; i++) {
				System.out.print(ciphertext[i].toString(16).toUpperCase());

				if (i != ciphertext.length - 1)
					System.out.print(" ");
			}
			System.out.println("]");
			System.out.println("");

			RSA.pr.println("");
			String recoveredPlaintext = rsa.decrypt(ciphertext);

			System.out.println("Recovered plaintext: [" + recoveredPlaintext + "]");
		}
		RSA.pr.println(" there statistics are for the different file sizes");
		RSA.pr.println("");
		RSA.pr.println("the order is .5KB , 1KB , 1.5 KB ,2 KB , 3.5 KB");
		RSA.pr.println("");
		String filenames[] = { "both.c", "README", "data", "er", "aas" };
		int keys[] = { 128, 256 };
		for (int i = 0; i < filenames.length; i++) {
			for (int j = 0; j < keys.length; j++) {

				BufferedReader in = new BufferedReader(new FileReader("/assign/" + filenames[i]));
				String s, plaintext1 = new String();
				while ((s = in.readLine()) != null)
					plaintext1 += s;
				in.close();

				RSA rsa1 = new RSA(keys[j]);

				System.out.println("Key Size: [" + keys[j] + "]");
				System.out.println("");

				System.out.println("Generated prime numbers p and q");
				System.out.println("p: [" + rsa1.getp().toString(16).toUpperCase() + "]");
				System.out.println("q: [" + rsa1.getq().toString(16).toUpperCase() + "]");
				System.out.println("");

				System.out.println("The public key is the pair (N, E) which will be published.");
				System.out.println("N: [" + rsa1.getN().toString(16).toUpperCase() + "]");
				System.out.println("E: [" + rsa1.getE().toString(16).toUpperCase() + "]");
				System.out.println("");

				System.out.println("The private key is the pair (N, D) which will be kept private.");
				System.out.println("N: [" + rsa1.getN().toString(16).toUpperCase() + "]");
				System.out.println("D: [" + rsa1.getD().toString(16).toUpperCase() + "]");
				System.out.println("");

				// Get message (plaintext) from user
				System.out.println("Please enter message (plaintext):");

				// String plaintext = ( new BufferedReader( new
				// InputStreamReader( System.in ) ) ).readLine() ;

				System.out.println(plaintext1);

				// Encrypt Message
				BigInteger[] ciphertext = rsa1.encrypt(plaintext1, keys[j] / 8);

				System.out.print("Ciphertext: [");
				for (int l = 0; l < ciphertext.length; l++) {
					System.out.print(ciphertext[l].toString(16).toUpperCase());

					if (l != ciphertext.length - 1)
						System.out.print(" ");
				}
				System.out.println("]");
				System.out.println("");

				String recoveredPlaintext = rsa1.decrypt(ciphertext);

				System.out.println("Recovered plaintext: [" + recoveredPlaintext + "]");
			}
		}

		RSA.pr.println("");
		RSA.pr.println("----------------------------------------------------");
		RSA.pr.println("");
		RSA.pr.println("");
		RSA.pr.println("");
		RSA.pr.println(
				" This section contains various statistics generated after varying probability of being an integer prime");
		int probability[] = { 5, 15, 25, 50 };
		for (int b = 0; b < probability.length; b++) {
			RSA.pr.println("");
			RSA.pr.println("the key generation time when probability is " + probability[b] + " : ");
			new RSA(512, probability[b]);
			RSA.pr.println("");

		}

	}

}