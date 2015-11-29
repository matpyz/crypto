import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.Scanner;

public interface PrivateKey extends PublicKey {
	class PrivateKeyImpl implements PrivateKey {
		private final BigInteger[] factors;
		private final BigInteger modulus;
		private final BigInteger privateExponent;
		private final BigInteger publicExponent;
		private final BigInteger totient;

		PrivateKeyImpl(final BigInteger[] factors, final BigInteger modulus, final BigInteger totient,
				final BigInteger publicExponent, final BigInteger privateExponent) {
			this.modulus = modulus;
			this.publicExponent = publicExponent;
			this.factors = factors;
			this.privateExponent = privateExponent;
			this.totient = totient;
		}

		@Override
		public BigInteger[] getFactors() {
			return factors;
		}

		@Override
		public BigInteger getModulus() {
			return modulus;
		}

		@Override
		public BigInteger getPrivateExponent() {
			return privateExponent;
		}

		@Override
		public BigInteger getPublicExponent() {
			return publicExponent;
		}

		@Override
		public BigInteger getTotient() {
			return totient;
		}

	}

	public static PrivateKey create(final BigInteger[] factors) {
		return create(factors, DEFAULT_EXPONENT);
	}

	public static PrivateKey create(final BigInteger[] factors, final BigInteger publicExponent) {
		BigInteger modulus = BigInteger.ONE;
		BigInteger totient = BigInteger.ONE;
		for (BigInteger factor : factors) {
			modulus = modulus.multiply(factor);
			totient = totient.multiply(factor.subtract(BigInteger.ONE));
		}
		final BigInteger privateExponent = publicExponent.modInverse(totient);
		return new PrivateKeyImpl(factors, modulus, totient, publicExponent, privateExponent);
	}

	public static PrivateKey load(InputStream input) {
		try (Scanner scanner = new Scanner(input)) {
			final BigInteger modulus = scanner.nextBigInteger();
			final BigInteger publicExponent = scanner.nextBigInteger();
			final BigInteger privateExponent = scanner.nextBigInteger();
			final BigInteger totient = scanner.nextBigInteger();
			final int k = scanner.nextInt();
			final BigInteger[] factors = new BigInteger[k];
			for (int i = 0; i < k; i++) {
				factors[i] = scanner.nextBigInteger();
			}
			return new PrivateKeyImpl(factors, modulus, totient, publicExponent, privateExponent);
		}
	}

	public static void save(PrintStream output, PrivateKey key) {
		output.println(key.getModulus());
		output.println(key.getPublicExponent());
		output.println(key.getPrivateExponent());
		output.println(key.getTotient());
		output.println(key.getFactors().length);
		for (BigInteger factor : key.getFactors()) {
			output.println(factor);
		}
	}

	public static PrivateKey swapExponents(final PrivateKey key) {
		return new PrivateKeyImpl(key.getFactors(), key.getModulus(), key.getTotient(), key.getPrivateExponent(),
				key.getPublicExponent());
	}

	public BigInteger[] getFactors();

	public BigInteger getPrivateExponent();

	public BigInteger getTotient();
}
