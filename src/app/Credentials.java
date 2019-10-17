package app;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.stream.Stream;

import org.apache.milagro.amcl.RAND;
import org.apache.milagro.amcl.FP256BN.*;

import app.Groth.GrothSignature;
import app.Util.eArg;

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
	
	public Proof Prove(RAND prg, BIG sk, Object pk, Index[] D, byte[] m, Object[][] grothYs, ECP h, BIG skNym) throws Exception {
	
		Proof proof = new Proof(); 
		
		int L = this.signatures.size() - 1;
		BIG q = new BIG(ROM.CURVE_Order);
		
		int[] n = new int[L+1];
		for (int i = 1; i <= L; i++) {
			n[i] = this.attributes.size();
		}
		
		BIG[] rhoSigma = new BIG[L+1];
		proof.rPrime = new Object[L+1];
		Object[] sPrime = new Object[L+1];
		Object[][] tPrime = new Object[L+1][];
		
		// line 2
		for (int i = 1; i <= L; i++) {
			// line 3
			rhoSigma[i] = BIG.randomnum(q, prg);
			proof.rPrime[i] = Util.pointMultiply(this.signatures.get(i).r, rhoSigma[i]);
			
			BIG rhoSigmaInv = new BIG(rhoSigma[i]);
			rhoSigmaInv.invmodp(q);
			sPrime[i] = Util.pointMultiply(this.signatures.get(i).s, rhoSigmaInv);
			
			// line 4
			tPrime[i] = new Object[n[i]+1];
			for (int j = 0; j < n[i]+1; j++) {
				// line 5
				tPrime[i][j] = Util.pointMultiply(this.signatures.get(i).ts[j], rhoSigmaInv);
			}
		}
		
		// line 8
		BIG[] rhoS = new BIG[L+1];
		BIG[][] rhoT = new BIG[L+1][];
		BIG[][] rhoA = new BIG[L+1][];
		BIG[] rhoCpk = new BIG[L+1];
		BIG rhoNym = BIG.randomnum(q, prg);
		
		for (int i = 1; i <= L; i++) {
			rhoS[i] = BIG.randomnum(q, prg);
			rhoCpk[i] = BIG.randomnum(q, prg);
			
			rhoT[i] = new BIG[n[i]+1];
			rhoA[i] = new BIG[n[i]];
			
			for (int j = 0; j < n[i]; j++) {
				rhoT[i][j] = BIG.randomnum(q, prg);
				rhoA[i][j] = BIG.randomnum(q, prg);
			}
			rhoT[i][n[i]] = BIG.randomnum(q, prg);
		}
		
		FP12[][] coms = new FP12[L+1][];
		int total = 0;
		for (int i = 1; i <= L; i++) {
			coms[i] = new FP12[n[i]+2];
			total+= n[i]+2;
		}
		
		// line 9 / 20
		for (int i = 1; i <= L; i++) {
			Object g1, g1Neg, g2, g2Neg;
			if (i %2 == 1) {
				g1 = ECP.generator();
				g2 = ECP2.generator();
			} else {
				g1 = ECP2.generator();
				g2 = ECP.generator();
			}
			g1Neg = Util.pointNegate(g1);
			g2Neg = Util.pointNegate(g2);
			
			// line 10 / 21
			BIG rhoSigmaS = BIG.modmul(rhoSigma[i], rhoS[i], q);
			eArg e1com1 = new eArg(g1, this.signatures.get(i).r, rhoSigmaS);
			eArg e2com1 = null;
			if (i != 1) {
				e2com1 = new eArg(g1Neg, g2, rhoCpk[i-1]);
			}
			eProductParallel(i, n[i], coms, e1com1, e2com1);
			
			// line 11 / 22
			BIG rhoSigmaT = BIG.modmul(rhoSigma[i], rhoT[i][0], q);
			eArg e1com2 = new eArg(g1, this.signatures.get(i).r, rhoSigmaT);
			eArg e2com2 = new eArg(g1, g2Neg, rhoCpk[i]);
			eArg e3com2 = null;
			if (i != 1) {
				e3com2 = new eArg(Util.pointNegate(grothYs[i%2][0]), g2, rhoCpk[i-1]);
			}
			eProductParallel(i, n[i]+1, coms, e1com2, e2com2, e3com2);
			
			// line 12 / 23
			for (int j = 0; j < n[i]; j++) {
				// line 13 / 24
				rhoSigmaT = BIG.modmul(rhoSigma[i], rhoT[i][j+1], q);
				
				// line 14 / 25
				eArg e1com = new eArg(g1, this.signatures.get(i).r, rhoSigmaT);
				eArg e2com = null;
				if (i != 1) {
					e2com = new eArg(Util.pointNegate(grothYs[i%2][j+1]), g2, rhoCpk[i-1]);
				}
				eArg e3com = null;
				if (Index.ContainedIn(D, i, j) == null) {
					// line 16 / 27
					e3com = new eArg(g1, g2Neg, rhoA[i][j]);
				}
				eProductParallel(i, j, coms, e1com, e2com, e3com);
			}
		}
		
		Object comNym = Util.productOfExponents(ECP.generator(), rhoCpk[L], h, rhoNym);
		
		// line 31
		
		
		return proof;
	}
	
	// 	wg.Wait()
	// 	close(communication)
	// 	for r := range communication {
	// 		if r.result == nil {
	// 			e = fmt.Errorf("error occurred in computing coms[%d][%d]", r.i, r.j)
	// 			return
	// 		}
	// 		coms[r.i][r.j] = r.result
	// 	}
	
	// 	comNym := productOfExponents(FP256BN.ECP_generator(), rhoCpk[L], h, rhoNym)
	
	// 	// line 31
	// 	proof.c = hashCommitments(grothYs, pk, proof.rPrime, coms, comNym, D, m, q)
	
	// 	// line 32 / 41
	// 	proof.resS = make([]interface{}, L+1)
	// 	proof.resT = make([][]interface{}, L+1)
	// 	proof.resA = make([][]interface{}, L+1)
	// 	proof.resCpk = make([]interface{}, L+1)
	
	// 	for i := 1; i <= L; i++ {
	// 		var g interface{}
	// 		if i%2 == 1 {
	// 			g = FP256BN.ECP_generator()
	// 		} else {
	// 			g = FP256BN.ECP2_generator()
	// 		}
	
	// 		// line 33 / 42
	// 		proof.resS[i] = productOfExponents(g, rhoS[i], sPrime[i], proof.c)
	// 		if i != L {
	// 			proof.resCpk[i] = productOfExponents(g, rhoCpk[i], creds.publicKeys[i], proof.c)
	// 		} else {
	// 			proof.resCsk = FP256BN.Modmul(proof.c, sk, q)
	// 			proof.resCsk = proof.resCsk.Plus(rhoCpk[L])
	// 			proof.resCsk.Mod(q)
	
	// 			proof.resNym = FP256BN.Modmul(proof.c, skNym, q)
	// 			proof.resNym = proof.resNym.Plus(rhoNym)
	// 			proof.resNym.Mod(q)
	// 		}
	
	// 		// line 34 / 43
	// 		proof.resT[i] = make([]interface{}, n[i]+1)
	// 		for j := 0; j < n[i]+1; j++ {
	// 			// line 35 / 44
	// 			proof.resT[i][j] = productOfExponents(g, rhoT[i][j], tPrime[i][j], proof.c)
	// 		}
	
	// 		// line 37 / 46
	// 		proof.resA[i] = make([]interface{}, n[i])
	// 		for j := 0; j < n[i]; j++ {
	// 			if D.contains(i, j) == nil {
	// 				// line 38 / 47
	// 				proof.resA[i][j] = productOfExponents(g, rhoA[i][j], creds.attributes[i][j], proof.c)
	// 			}
	// 		}
	// 	}
	
	// 	return
	// }
	
	private BIG hashCommitments(Object[][] grothYs, Object pk, Object[] rPrime, FP12[][] coms, Object comNym, Index[] D, byte[] m, BIG q) {
		ByteArrayOutputStream raw = new ByteArrayOutputStream( );
		
		for (int i = 0; i < grothYs.length; i++) {
			for (int j = 0; j < grothYs[i%2]; j++) {
				
			}
		}
	}
	
	// func hashCommitments(grothYs [][]interface{}, pk PK, rPrime []interface{}, coms [][]*FP256BN.FP12, comNym interface{}, D Indices, m []byte, q *FP256BN.BIG) *FP256BN.BIG {

	// 	var raw []byte
	
	// 	for i := 0; i < len(grothYs); i++ {
	// 		for j := 0; j < len(grothYs[i%2]); j++ {
	// 			raw = append(raw, pointToBytes(grothYs[i%2][j])...)
	// 		}
	// 	}
	// 	raw = append(raw, pointToBytes(pk)...)
	// 	for i := 0; i < len(rPrime); i++ {
	// 		if rPrime[i] != nil {
	// 			raw = append(raw, pointToBytes(rPrime[i])...)
	// 		}
	// 	}
	// 	for i := 0; i < len(coms); i++ {
	// 		for j := 0; j < len(coms[i]); j++ {
	// 			if coms[i][j] != nil {
	// 				raw = append(raw, fpToBytes(coms[i][j])...)
	// 			}
	// 		}
	// 	}
	// 	raw = append(raw, pointToBytes(comNym)...)
	// 	raw = append(raw, D.hash()...)
	// 	raw = append(raw, m...)
	
	// 	return sha3(q, raw)
	// }
	
	
	private void eProductParallel(int i, int j, FP12[][] coms, eArg... args) {
		coms[i][j] = Util.eProduct(args);
	}
}
