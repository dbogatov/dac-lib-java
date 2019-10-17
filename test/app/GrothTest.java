package app;

import static org.junit.Assert.assertEquals;

import org.apache.milagro.amcl.RAND;
import org.junit.Test;

public class GrothTest {

	static byte SEED = 0x13;

	@Test(expected = Test.None.class)
	public void happyPath() throws Exception {

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		for (boolean first : new boolean[] { true, false }) {

			Object[] grothMessage = new Object[] { Util.StringToECPb("hello", first), Util.StringToECPb("world", first),
					Util.StringToECPb("!", first) };

			Groth groth = new Groth(prg, first, Groth.GenerateYs(first, 3, prg));

			KeyPair keyPair = groth.Generate();

			Groth.GrothSignature signature = groth.Sign(keyPair.sk, grothMessage);

			groth.Verify(keyPair.pk, signature, grothMessage);
		}
	}

	@Test(expected = Exception.class)
	public void sadPath() throws Exception {

		RAND prg = new RAND();

		prg.clean();
		prg.seed(1, new byte[] { SEED });

		for (boolean first : new boolean[] { true, false }) {

			Object[] grothMessage = new Object[] { Util.StringToECPb("hello", first), Util.StringToECPb("world", first),
					Util.StringToECPb("!", first) };
			Object[] badMessage = new Object[] { Util.StringToECPb("hello", first), Util.StringToECPb("world", first),
					Util.StringToECPb("?", first) };

			Groth groth = new Groth(prg, first, Groth.GenerateYs(first, 3, prg));

			KeyPair keyPair = groth.Generate();

			Groth.GrothSignature signature = groth.Sign(keyPair.sk, badMessage);

			groth.Verify(keyPair.pk, signature, grothMessage);
		}
	}
}