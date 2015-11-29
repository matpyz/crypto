import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;

public class RsaCipher extends Thread {
	public static BigInteger decode(final BigInteger ciphertext, final PrivateKey key) throws InterruptedException {
		final BigInteger[] factors = key.getFactors();
		final int k = factors.length;
		final RsaCipher[] threads = new RsaCipher[k];
		final BigInteger[] result = new BigInteger[k];
		BigInteger message = BigInteger.ZERO;
		for (int i = 0; i < k; i++) {
			threads[i] = new RsaCipher(key, ciphertext, result, i);
		}
		for (int i = 0; i < k; i++) {
			threads[i].join();
			message = message.add(result[i]);
		}
		message = message.remainder(key.getModulus());
		return message;
	}

	public static BigInteger encode(final BigInteger message, final PublicKey key) {
		return message.modPow(key.getPublicExponent(), key.getModulus());
	}

	public static PrivateKey generate(final int k, final int d) throws InterruptedException {
		final BigInteger[] factors = PrimeGenerator.distinctPrimes(k, d);
		return PrivateKey.create(factors);
	}

	public static void main(String[] args) {
		try {
			switch (args[0]) {
			case "gen": {
				final int k = Integer.parseInt(args[1]);
				final int d = Integer.parseInt(args[2]);
				final PrivateKey key = generate(k, d);
				try (PrintStream prv = new PrintStream("id_rsa"); PrintStream pub = new PrintStream("id_rsa.pub")) {
					PrivateKey.save(prv, key);
					PublicKey.save(pub, key);
				}
				return;
			}
			case "enc": {
				if (args.length == 2 && args[1].equals("crt")) {
					try (InputStream prv = new FileInputStream("id_rsa")) {
						final PrivateKey key = PrivateKey.swapExponents(PrivateKey.load(prv));
						final int max = key.getModulus().bitLength() / 8 - 1;
						final byte[] buffer = new byte[max];
						byte[] trimmedBuffer;
						int len;
						buffer[0] = 1;
						while ((len = System.in.read(buffer, 1, max-1)) != -1) {
							if (len < max-1) {
								trimmedBuffer = Arrays.copyOfRange(buffer, 0, len);
							} else {
								trimmedBuffer = buffer;
							}
							final BigInteger in = new BigInteger(trimmedBuffer);
							final BigInteger out = decode(in, key);
							System.out.println(out.toString(16));
						}
					}
				} else {
					try (InputStream pub = new FileInputStream("id_rsa.pub")) {
						final PublicKey key = PublicKey.load(pub);
						final int max = key.getModulus().bitLength() / 8 - 1;
						final byte[] buffer = new byte[max];
						byte[] trimmedBuffer;
						int len;
						buffer[0] = 1;
						while ((len = System.in.read(buffer)) != -1) {
							if (len < max-1) {
								trimmedBuffer = Arrays.copyOfRange(buffer, 0, len);
							} else {
								trimmedBuffer = buffer;
							}
							final BigInteger in = new BigInteger(trimmedBuffer);
							final BigInteger out = encode(in, key);
							System.out.println(out.toString(16));
						}
					}
				}
				return;
			}
			case "dec": {
				if (args.length == 2 && args[1].equals("crt")) {
					try (InputStream prv = new FileInputStream("id_rsa"); Scanner scanner = new Scanner(System.in)) {
						final PrivateKey key = PrivateKey.load(prv);
						while (scanner.hasNextBigInteger(16)) {
							final BigInteger in = scanner.nextBigInteger(16);
							final BigInteger out = decode(in, key);
							System.out.write(out.toByteArray());
							System.out.write(Arrays.copyOfRange(out.toByteArray(), 1, out.toByteArray().length));
						}
					}
				} else {
					try (InputStream prv = new FileInputStream("id_rsa"); Scanner scanner = new Scanner(System.in)) {
						final PublicKey key = PrivateKey.swapExponents(PrivateKey.load(prv));
						while (scanner.hasNextBigInteger(16)) {
							final BigInteger in = scanner.nextBigInteger(16);
							final BigInteger out = encode(in, key);
							System.out.write(Arrays.copyOfRange(out.toByteArray(), 1, out.toByteArray().length));
						}
					}
				}
				return;
			}
			default:
				System.err.println("gen/enc/dec option expected");
			}
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
	}

	private final BigInteger ciphertext;

	private final int i;

	private final PrivateKey key;

	private final BigInteger[] result;

	public RsaCipher(PrivateKey key, BigInteger ciphertext, BigInteger[] result, int i) {
		this.key = key;
		this.ciphertext = ciphertext;
		this.result = result;
		this.i = i;
		start();
	}

	@Override
	public void run() {
		final BigInteger p = key.getFactors()[i];
		final BigInteger d = key.getPrivateExponent().mod(p.subtract(BigInteger.ONE));
		final BigInteger m = ciphertext.modPow(d, p);
		final BigInteger n = key.getModulus().divide(p);
		result[i] = n.modInverse(p).multiply(m).multiply(n);
	}
}
