package app;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

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

		chain.skNym = new BIG(1); // TODO implement nyms

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
}