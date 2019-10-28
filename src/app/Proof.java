package app;

import org.apache.milagro.amcl.FP256BN.*;

public class Proof {
	BIG c;
	Object[] rPrime;
	Object[] resS;
	Object[][] resT;
	Object[][] resA;
	Object[] resCpk;
	BIG resCsk;
	BIG resNym;

	public void VerifyProof(Object pk, Object[][] grothYs, ECP h, Object pkNym, Index[] D, byte[] m) throws Exception {
		int L = this.resA.length - 1;
		BIG q = new BIG(ROM.CURVE_Order);

		int[] n = new int[L + 1];
		for (int i = 1; i <= L; i++) {
			n[i] = this.resA[i].length;
		}

		FP12[][] coms = new FP12[L + 1][];
		for (int i = 1; i <= L; i++) {
			coms[i] = new FP12[n[i] + 2];
		}

		BIG cNeg = Util.bigNegate(this.c, q);

		// line 3
		for (int i = 1; i <= L; i++) {
			Object g1, g1Neg, g2, g2Neg;
			if (i % 2 == 1) {
				g1 = ECP.generator();
				g2 = ECP2.generator();
			} else {
				g1 = ECP2.generator();
				g2 = ECP.generator();
			}
			g1Neg = Util.pointNegate(g1);
			g2Neg = Util.pointNegate(g2);

			coms[i] = new FP12[n[i] + 2];

			// line 4
			eArg e1com1 = new eArg(this.resS[i], this.rPrime[i], null);
			eArg e2com1 = null;
			if (i != 1) {
				e2com1 = new eArg(g1Neg, this.resCpk[i - 1], null);
			}
			eArg e3com1 = new eArg(grothYs[i % 2][0], g2, cNeg);
			eArg e4com1 = null;
			if (i == 1) {
				e4com1 = new eArg(g1, pk, cNeg);
			}
			Util.eProductParallel(i, n[i], coms, e1com1, e2com1, e3com1, e4com1);

			// line 5
			eArg e1com2 = new eArg(this.resT[i][0], this.rPrime[i], null);
			eArg e2com2 = null;
			if (i != 1) {
				e2com2 = new eArg(Util.pointNegate(grothYs[i % 2][0]), this.resCpk[i - 1], null);
			}
			eArg e3com2 = null;
			if (i != L) {
				e3com2 = new eArg(this.resCpk[i], g2Neg, null);
			}
			eArg e4com2 = null;
			if (i == L) {
				e4com2 = new eArg(g1, g2Neg, this.resCsk);
			}
			eArg e5com2 = null;
			if (i == 1) {
				e5com2 = new eArg(grothYs[i % 2][0], pk, cNeg);
			}
			Util.eProductParallel(i, n[i] + 1, coms, e1com2, e2com2, e3com2, e4com2, e5com2);

			// line 6
			for (int j = 0; j < n[i]; j++) {
				// line 7
				Object attribute = Index.ContainedIn(D, i, j);
				if (attribute != null) {
					// line 8
					eArg e1com = new eArg(this.resT[i][j + 1], this.rPrime[i], null);
					eArg e2com = null;
					if (i != 1) {
						e2com = new eArg(Util.pointNegate(grothYs[i % 2][j + 1]), this.resCpk[i - 1], null);
					}
					eArg e3com = new eArg(attribute, g2, cNeg);
					eArg e4com = null;
					if (i == 1) {
						e4com = new eArg(grothYs[i % 2][j + 1], pk, cNeg);
					}
					Util.eProductParallel(i, j, coms, e1com, e2com, e3com, e4com);
				} else {
					// line 10
					eArg e1com = new eArg(this.resT[i][j + 1], this.rPrime[i], null);
					eArg e2com = new eArg(this.resA[i][j], g2Neg, null);
					eArg e3com = null;
					if (i != 1) {
						e3com = new eArg(Util.pointNegate(grothYs[i % 2][j + 1]), this.resCpk[i - 1], null);
					}
					eArg e4com = null;
					if (i == 1) {
						e4com = new eArg(grothYs[i % 2][j + 1], pk, cNeg);
					}
					Util.eProductParallel(i, j, coms, e1com, e2com, e3com, e4com);
				}
			}
		}

		Object comNym = Util.productOfExponents(ECP.generator(), this.resCsk, h, this.resNym);
		Util.pointSubtract(comNym, Util.pointMultiply(pkNym, this.c));

		// line 25
		BIG cPrime = Util.hashCommitments(grothYs, pk, this.rPrime, coms, comNym, D, m, q);

		if (!Util.bigEqual(this.c, cPrime)) {
			throw new Exception("proof verification failed");
		}
	}
}