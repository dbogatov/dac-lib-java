package app;

import org.apache.milagro.amcl.RAND;
import org.apache.milagro.amcl.FP256BN.*;
import org.junit.Test;

public class CredentialsTest {

	class Chain {
		Credentials creds;
		KeyPair keys;
		Object[][] ys;
		ECP h;
		BIG skNym;
		Object pkNym;
	}

	static byte SEED = 0x13;

	private Chain generateChain(int L, int n) {
		Chain chain = new Chain();

		final int YsNum = 10;

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		chain.keys = Credentials.GenerateKeys(prg, 0);
		chain.creds = new Credentials(chain.keys.pk);

		chain.ys = new Object[2][];
		chain.ys[0] = Groth.GenerateYs(false, YsNum, prg);
		chain.ys[1] = Groth.GenerateYs(true, YsNum, prg);

		chain.h = ECP.generator().mul(BIG.randomnum(new BIG(ROM.CURVE_Order), prg));

		for (int index = 1; index <= L; index++) {
			KeyPair iKyes = Credentials.GenerateKeys(prg, index);
			String[] values = new String[n];
			for (int j = 0; j < n; j++) {
				values[j] = "attribute-" + index + "-" + j;
			}
			Object[] ai = Credentials.ProduceAttributes(index, values);

			chain.creds.Delegate(chain.keys.sk, iKyes.pk, ai, prg, chain.ys);
			chain.keys.sk = iKyes.sk;
		}

		// TODO implement nyms
		chain.skNym = new BIG(1);
		chain.pkNym = ECP.generator().mul(BIG.randomnum(new BIG(ROM.CURVE_Order), prg));

		return chain;
	}

	@Test(expected = Test.None.class)
	public void happyPathVerify() throws Exception {

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		int L = 10;

		Chain chain = generateChain(L, 3);

		chain.creds.Verify(chain.keys.sk, chain.keys.pk, chain.ys);
	}

	@Test(expected = Test.None.class)
	public void happyPathProve() throws Exception {

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		int L = 10;

		Chain chain = generateChain(L, 3);

		chain.creds.Prove(prg, chain.keys.sk, chain.keys.pk,
				new Index[] { new Index(1, 1, chain.creds.attributes.get(1)[1]) }, "Message".getBytes(), chain.ys,
				chain.h, chain.skNym);
	}

	@Test(expected = Test.None.class)
	public void happyPathVerifyProof() throws Exception {

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		int L = 10;

		Chain chain = generateChain(L, 3);

		for (int i = 0; i < 2; i++) {
			Index[] D;
			if (i == 0) {
				D = new Index[] { new Index(4, 1, chain.creds.attributes.get(4)[1]) };
			} else {
				D = new Index[] {};
			}

			byte[] m = "Message".getBytes();

			Proof proof = chain.creds.Prove(prg, chain.keys.sk, chain.keys.pk, D, m, chain.ys, chain.h, chain.skNym);

			proof.VerifyProof(chain.keys.pk, chain.ys, chain.h, chain.pkNym, D, m);
		}

		// Following commented code may be used for debugging
		// If proof.VerifyProof returns comsVer of type FP12[][] with coms values
		// and Proof has a field coms of the same type, then the follwoing will
		// compare the commitment values pairwise

		/*
		for (int i = 0; i < comsVer.length; i++) {
			if (comsVer[i] == null) {
				System.out.println("comsVer[" + i + "] and proof.coms[" + i + "] are "
						+ (proof.coms[i] == null ? "" : "not ") + "both null");
			} else {
				for (int j = 0; j < comsVer[i].length; j++) {
					System.out.println("proof.coms[" + i + "][" + j + "] "
							+ (proof.coms[i][j].equals(comsVer[i][j]) ? "==" : " !=") + " comsVer[" + i + "][" + j
							+ "]");
				}
			}
		}
		*/
	}

	@Test(expected = Exception.class)
	public void sadPathVerifyProof() throws Exception {

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		int L = 10;

		Chain chain = generateChain(L, 3);

		Index[] D = new Index[] { new Index(1, 1, chain.creds.attributes.get(1)[1]) };
		byte[] m = "Message".getBytes();

		Proof proof = chain.creds.Prove(prg, chain.keys.sk, chain.keys.pk, D, m, chain.ys, chain.h, chain.skNym);

		// tamper
		if (proof.rPrime[5] instanceof ECP) {
			proof.rPrime[5] = ECP.generator().mul(BIG.randomnum(new BIG(ROM.CURVE_Order), prg));
		} else {
			proof.rPrime[5] = ECP2.generator().mul(BIG.randomnum(new BIG(ROM.CURVE_Order), prg));
		}

		proof.VerifyProof(chain.keys.pk, chain.ys, chain.h, chain.pkNym, D, m);
	}
}