package main.java;

import java.util.ArrayList;
import java.util.stream.Stream;

import org.apache.milagro.amcl.RAND;
import org.apache.milagro.amcl.FP256BN.*;

import main.java.Groth.GrothSignature;

public class Credentials {

	ArrayList<GrothSignature> signatures;
	ArrayList<Object[]> attributes;
	ArrayList<Object> publicKeys;

	public Credentials(Object pk) {
		this.signatures = new ArrayList<>();
		this.signatures.add(null);

		this.attributes = new ArrayList<>();
		this.attributes.add(new Object[] {});

		this.publicKeys = new ArrayList<>();
		this.publicKeys.add(pk);
	}

	public static KeyPair GenerateKeys(RAND prg, int L) {
		return new Groth(prg, L % 2 != 1, new Object[] {}).Generate();
	}

	public static Object[] ProduceAttributes(int L, String... inputs) {

		boolean first = L % 2 == 1;
		Object[] attributes = new Object[inputs.length];
		for (int index = 0; index < inputs.length; index++) {
			attributes[index] = Util.StringToECPb(inputs[index], first);
		}

		return attributes;
	}

	public void Delegate(BIG sk, Object publicKey, Object[] attributes, RAND prg, Object[][] grothYs) {

		int L = this.signatures.size();

		Groth groth = new Groth(prg, L % 2 == 1, grothYs[L % 2]);

		GrothSignature sigma = groth.Sign(sk,
				Stream.of(new Object[] { publicKey }, attributes).flatMap(Stream::of).toArray());

		this.attributes.add(attributes);
		this.signatures.add(sigma);
		this.publicKeys.add(publicKey);
	}

	public void Verify(BIG sk, Object authorityPK, Object[][] grothYs) throws Exception {
		int L = this.signatures.size();

		if (L == 0) {
			throw new Exception("empty credentials");
		}

		if (!Util.pkEqual(authorityPK, this.publicKeys.get(0))) {
			throw new Exception("trusted authority's public key and credentials' top-level public key do not match");
		}

		for (int index = L - 1; index > 0; index--) {
			Groth groth = new Groth(null, index % 2 == 1, grothYs[index % 2]);
			try {
				groth.Verify(this.publicKeys.get(index - 1), this.signatures.get(index),
				Stream.of(new Object[] { this.publicKeys.get(index) }, this.attributes.get(index)).flatMap(Stream::of).toArray());
			} catch (Exception e) {
				throw new Exception("verification failed for L = " + index);
			}
		}

		if (!Util.VerifyKeyPair(sk, this.publicKeys.get(publicKeys.size() - 1))) {
			throw new Exception("supplied secret key does not match credentials' bottom-level public key");
		}
	}
}
