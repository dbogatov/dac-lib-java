package main.java;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.apache.milagro.amcl.RAND;
import org.junit.Test;

public class CredentialsTest {

	class Chain {
		Credentials creds;
		KeyPair keys;
		Object[][] ys;
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

		return chain;
	}

	@Test(expected = Test.None.class)
	public void happyPath() throws Exception {

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		int L = 10;

		Chain chain = generateChain(L, 3);

		chain.creds.Verify(chain.keys.sk, chain.keys.pk, chain.ys);
	}
}