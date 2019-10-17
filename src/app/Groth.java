package app;

import org.apache.milagro.amcl.RAND;
import org.apache.milagro.amcl.FP256BN.*;

public class Groth {

	BIG q;
	RAND prg;
	Object g1;
	Object g2;
	Object[] y;

	class GrothSignature {
		Object r;
		Object s;
		Object[] ts;

		public boolean equals(GrothSignature other) {
			if (!Util.pointEqual(this.r, other.r)) {
				return false;
			}

			if (!Util.pointEqual(this.s, other.s)) {
				return false;
			}

			if (!Util.pointListEquals(this.ts, other.ts)) {
				return false;
			}

			return true;
		}
	}

	public Groth(RAND prg, boolean first, Object[] ys) {
		this.q = new BIG(ROM.CURVE_Order);
		this.prg = prg;

		if (first) {
			this.g1 = ECP.generator();
			this.g2 = ECP2.generator();
		} else {
			this.g1 = ECP2.generator();
			this.g2 = ECP.generator();
		}

		this.y = ys;
	}

	public KeyPair Generate() {
		KeyPair result = new KeyPair();

		result.sk = BIG.randomnum(this.q, this.prg);
		result.pk = Util.pointMultiply(this.g2, result.sk);

		return result;
	}

	public GrothSignature Sign(BIG sk, Object[] m) {
		GrothSignature signature = new GrothSignature();

		try {
			this.consistencyCheck(m);
		} catch (Exception e) {
			return null;
		}

		BIG rRand = BIG.randomnum(this.q, this.prg);

		signature.r = Util.pointMultiply(this.g2, rRand);

		BIG rInv = Util.bigInverse(rRand, this.q);

		signature.s = Util.pointMultiply(this.g1, sk);
		Util.pointAdd(signature.s, this.y[0]);
		signature.s = Util.pointMultiply(signature.s, rInv);

		signature.ts = new Object[m.length];

		for (int index = 0; index < m.length; index++) {
			Object T = Util.pointMultiply(this.y[index], sk);
			Util.pointAdd(T, m[index]);
			signature.ts[index] = Util.pointMultiply(T, rInv);
		}

		return signature;
	}

	public void Verify(Object pk, GrothSignature signature, Object[] m) throws Exception {

		this.consistencyCheck(m);
		this.consistencyCheck(signature.ts);

		if (m.length != signature.ts.length) {
			throw new Exception("m (" + m.length + ") must be equal to Ts (" + signature.ts.length + ")");
		}

		FP12 eLHS = PAIR.fexp(Util.ate(signature.r, signature.s));
		FP12 eRHS = PAIR.fexp(Util.ate2(this.g2, this.y[0], pk, this.g1));

		if (!eLHS.equals(eRHS)) {
			throw new Exception(
					"verification failed for the first predicate (message independent, if many errors, this is the last)");
		}

		for (int index = 0; index < m.length; index++) {

			eLHS = PAIR.fexp(Util.ate(signature.r, signature.ts[index]));
			eRHS = PAIR.fexp(Util.ate2(pk, this.y[index], this.g2, m[index]));

			if (!eLHS.equals(eRHS)) {
				throw new Exception("verification failed for the " + index + "-th message");
			}
		}
	}

	public GrothSignature Randomize(GrothSignature signature, BIG rPrime) throws Exception {
		GrothSignature signaturePrime = new GrothSignature();

		this.consistencyCheck(signature.ts);

		if (rPrime == null) {
			rPrime = BIG.randomnum(this.q, this.prg);
		} else {
			rPrime.mod(this.q);
		}
		BIG rPrimeInv = Util.bigInverse(rPrime, this.q);

		signaturePrime.r = Util.pointMultiply(signature.r, rPrime);
		signaturePrime.s = Util.pointMultiply(signature.s, rPrimeInv);

		signaturePrime.ts = new Object[signature.ts.length];
		for (int index = 0; index < signature.ts.length; index++) {
			signaturePrime.ts[index] = Util.pointMultiply(signature.ts[index], rPrimeInv);
		}

		return signaturePrime;
	}

	public static Object[] GenerateYs(boolean first, int n, RAND prg) {
		BIG q = new BIG(ROM.CURVE_Order);
		Object g;
		if (first) {
			g = ECP.generator();
		} else {
			g = ECP2.generator();
		}

		Object[] ys = new Object[n];
		for (int index = 0; index < n; index++) {
			BIG a = BIG.randomnum(q, prg);
			ys[index] = Util.pointMultiply(g, a);
		}

		return ys;
	}

	private void consistencyCheck(Object[] arg) throws Exception {
		if (arg.length > this.y.length) {
			throw new Exception("wrong argument length supplied (" + arg.length + "), must at most " + this.y.length);
		}
	}
}
