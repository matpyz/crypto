import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.SortedSet;
import java.util.TreeSet;

public class PrimeGenerator extends Thread {
	public static BigInteger[] distinctPrimes(final int k, final int d) throws InterruptedException {
		final SortedSet<BigInteger> primes = new TreeSet<>();
		final PrimeGenerator[] threads = new PrimeGenerator[k];
		for (int i = 0; i < k; i++) {
			threads[i] = new PrimeGenerator(d, primes);
		}
		for (int i = 0; i < k; i++) {
			threads[i].join();
		}
		return primes.toArray(new BigInteger[k]);
	}
	public static void main(String[] args) throws InterruptedException {
		if(args.length != 2)
			return;
		final int k = Integer.parseInt(args[0]);
		final int d = Integer.parseInt(args[1]);
		BigInteger[] primes = distinctPrimes(k, d);
		for (BigInteger prime : primes) {
			System.out.println(prime);
		}
	}

	private final int d;

	private SortedSet<BigInteger> primes;

	public PrimeGenerator(final int d, final SortedSet<BigInteger> primes) {
		this.d = d;
		this.primes = primes;
		start();
	}

	@Override
	public void run() {
		final Random random = new SecureRandom();
		BigInteger prime;
		boolean done;
		do {
			prime = BigInteger.probablePrime(d, random);
			synchronized (primes) {
				done = primes.add(prime);
			}
		} while (!done);
	}
}
