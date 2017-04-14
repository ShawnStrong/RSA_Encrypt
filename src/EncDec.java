import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.xml.bind.DatatypeConverter;

public class EncDec {
	public static final String publicKeyFile = "src/message.txt";
	public static final Charset encoding = Charset.defaultCharset();

	public static String hexMessage = "";
	public static BigInteger encMessage, decMessage;
	public static BigInteger p, q, d, n;
	public static BigInteger phi = new BigInteger("0");

	public static final String stringe = "65537";
	public static final BigInteger e = new BigInteger(stringe);

	public static final BigInteger almostdif = new BigInteger("2");
	public static final BigInteger dif = almostdif.pow(800);

	public static final BigInteger almostmin = new BigInteger("2");
	public static final BigInteger min = almostmin.pow(1536);

	public static final BigInteger gcd = new BigInteger("1");

	public static void main(String[] args) throws IOException {

		File incomingFile = new File(publicKeyFile);

		System.out.println("Input message:");

		// reads file and converts message to plaintext
		handleFile(incomingFile);
		
		
		fromHex(hexMessage);

		// generates p, q, and n. This method satisfies special conditions when
		// generating these numbers
		generatepandq();
		
		encryptMessage();
		
		decryptMessage();

	}

	private static void handleFile(File file) throws IOException {
		try (InputStream in = new FileInputStream(file);
				Reader reader = new InputStreamReader(in, encoding);
				// buffer for efficiency
				Reader buffer = new BufferedReader(reader)) {
			handleCharacters(buffer);
		}
	}

	private static void handleCharacters(Reader reader) throws IOException {
		int r;
		StringBuilder s = new StringBuilder();
		while ((r = reader.read()) != -1) {
			char ch = (char) r;
			s.append(ch);
			System.out.print(ch);
		}

		System.out.println();
		System.out.println();
		System.out.println("Recorded string:");
		System.out.println(s.toString());
		
		hexMessage = toHex(s.toString());
		
		System.out.println("Hex: ");
		System.out.println(hexMessage);
		
		/*decMessage = toDec(hexMessage);
		
		System.out.println("Dec: ");
		System.out.println(decMessage);
		System.out.println();*/
	}

	public static String toHex(String arg) {
		return String.format("%040x", new BigInteger(1, arg.getBytes(encoding)));
	}
	
	public static void fromHex(String arg){
		byte[] bytes = DatatypeConverter.parseHexBinary(arg);
		String result= new String(bytes, encoding);
		System.out.println("fromHex: ");
		System.out.println(result);
		System.out.println();
	}
	
	/*public static String toDec(String s) {
        String digits = "0123456789ABCDEF";
        s = s.toUpperCase();
        int val = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = digits.indexOf(c);
            val = 16*val + d;
        }
        return Integer.toString(val);
    }*/

	private static void generatepandq() {
		
		BigInteger realD = new BigInteger("0");
		final int PRIME_CERTAINTY = 100;
		final int BITLENGTH = 2048;
		BigInteger result;
		
		do {
			do {
				do {
					p = BigInteger.probablePrime(BITLENGTH, new SecureRandom());
				} while (!p.isProbablePrime(PRIME_CERTAINTY) && p.compareTo(min) == -1);

				do {
					q = BigInteger.probablePrime(BITLENGTH, new SecureRandom());
				} while (!q.isProbablePrime(PRIME_CERTAINTY) && q.compareTo(min) == -1 || q.equals(p));
				realD = p.subtract(q).abs();
			} while (realD.compareTo(dif) == -1);
			n = p.multiply(q);
			phi = (p.subtract(gcd)).multiply(q.subtract(gcd));
			result = phi.gcd(e);
		} while (result.compareTo(gcd) != 0);

		System.out.println("p = " + p);
		System.out.println("q = " + q);
		System.out.println("n = " + n);
		System.out.println("gcd n and e = " + phi.gcd(e));

	}
	
	private static void encryptMessage(){
		
		BigInteger eHex=new BigInteger(e.toString(),16);
		BigInteger nHex = new BigInteger(n.toString(), 16);
		
		System.out.println();
		System.out.println("eHex = " + eHex);
		System.out.println("nHex = " + nHex);
		
		BigInteger hexMessageInt = new BigInteger(hexMessage, 16);
		encMessage = hexMessageInt.modPow(e, n);
		
		System.out.println();
		System.out.println("Encrypted message: ");
		System.out.println(encMessage);
	}
	
	private static void decryptMessage(){
		
		d = e.modInverse(phi);
		BigInteger dHex = new BigInteger(d.toString(), 16);
		BigInteger nHex = new BigInteger(n.toString(), 16);
		
		System.out.println();
		System.out.println("dHex = " + dHex);
		System.out.println("nHex = " + nHex);
		
		decMessage = encMessage.modPow(d, n);
		
		System.out.println();
		fromHex(decMessage.toString());
		
	}

}
