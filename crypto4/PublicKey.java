import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.Scanner;

public interface PublicKey {
	class PublicKeyImpl implements PublicKey {

		private final BigInteger modulus;
		private final BigInteger publicExponent;

		PublicKeyImpl(final BigInteger modulus, final BigInteger publicExponent) {
			this.modulus = modulus;
			this.publicExponent = publicExponent;
		}

		@Override
		public BigInteger getModulus() {
			return modulus;
		}

		@Override
		public BigInteger getPublicExponent() {
			return publicExponent;
		}
	}

	public static final BigInteger DEFAULT_EXPONENT = new BigInteger(new byte[] { 1, 0, 1 });

	public static PublicKey create(final BigInteger modulus) {
		return create(modulus, DEFAULT_EXPONENT);
	}

	public static PublicKey create(final BigInteger modulus, final BigInteger publicExponent) {
		return new PublicKeyImpl(modulus, publicExponent);
	}
	
	public static PublicKey load(InputStream input) {
		try (Scanner scanner = new Scanner(input)) {
			final BigInteger modulus = scanner.nextBigInteger();
			final BigInteger publicExponent = scanner.nextBigInteger();
			return create(modulus, publicExponent);
		}
	}

	public static void save(PrintStream output, PublicKey key) {
		output.println(key.getModulus());
		output.println(key.getPublicExponent());
	}

	public BigInteger getModulus();

	public BigInteger getPublicExponent();
}
