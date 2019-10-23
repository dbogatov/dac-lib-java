package app;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.nio.ByteBuffer;

import org.apache.milagro.amcl.SHA3;
import org.apache.milagro.amcl.FP256BN.*;

public class Util {

	public static boolean _OptimizeTate;

	public static final int _BIGByteLength = 32;
	public static final int _ECPByteLength = 1 + 2 * _BIGByteLength;
	public static final int _ECP2ByteLength = 4 * _BIGByteLength;
	public static final int _FP12ByteLength = 12 * _BIGByteLength;

	// Equality checks

	public boolean bytesEqual(byte[] first, byte[] second) {
		if (first.length != second.length) {
			return false;
		}

		for (int index = 0; index < first.length; index++) {
			if (first[index] != second[index]) {
				return false;
			}
		}

		return true;
	}

	public static boolean bigEqual(BIG a, BIG b) {
		byte[] A = new byte[_BIGByteLength];
		byte[] B = new byte[_BIGByteLength];

		for (int index = 0; index < _BIGByteLength; index++) {
			if (A[index] != B[index]) {
				return false;
			}
		}

		return true;
	}

	public static boolean pointEqual(Object g, Object h) {
		if (g == null || h == null) {
			return g == null && h == null;
		}

		if (g instanceof ECP) {
			return ((ECP) g).equals((ECP) h);
		} else {
			return ((ECP2) g).equals((ECP2) h);
		}

	}

	public static boolean pointListEquals(Object[] gs, Object[] hs) {
		if (gs.length != hs.length) {
			return false;
		}

		for (int index = 0; index < gs.length; index++) {
			if (!pointEqual(gs[index], hs[index])) {
				return false;
			}
		}

		return true;
	}

	public static boolean pointListOfListEquals(Object[][] gss, Object[][] hss) {
		if (gss.length != hss.length) {
			return false;
		}

		for (int index = 0; index < gss.length; index++) {
			if (!pointListEquals(gss[index], hss[index])) {
				return false;
			}
		}

		return true;
	}

	// Arithmetic

	public static BIG bigMinusMod(BIG a, BIG b, BIG m) {
		BIG result;

		BIG aNorm = new BIG(a);
		BIG bNorm = new BIG(b);

		aNorm.norm();
		bNorm.norm();

		if (BIG.comp(aNorm, bNorm) >= 0) {
			result = a.minus(b);
			result.mod(m);
			return result;
		}

		aNorm.mod(m);
		bNorm.mod(m);
		result = aNorm.minus(bNorm);

		return result.plus(m);
	}

	public static BIG bigNegate(BIG a, BIG q) {
		return bigMinusMod(new BIG(0), a, q);
	}

	public static BIG bigInverse(BIG a, BIG q) {
		BIG aInv = new BIG(a);
		aInv.invmodp(q);

		return aInv;
	}

	public static Object pointNegate(Object g) {
		Object result;

		if (g instanceof ECP) {
			result = new ECP();
			((ECP) result).copy((ECP) g);
			((ECP) result).neg();
		} else {
			result = new ECP2();
			((ECP2) result).copy((ECP2) g);
			((ECP2) result).neg();
		}

		return result;
	}

	public static Object productOfExponents(Object g, BIG a, Object h, BIG b) {
		Object c;

		if (g instanceof ECP) {
			c = ((ECP) g).mul2(a, (ECP) h, b);
		} else {
			c = pointMultiply(g, a);
			pointAdd(c, pointMultiply(h, b));
		}

		return c;
	}

	public static void pointAdd(Object g, Object h) {
		if (g instanceof ECP) {
			((ECP) g).add((ECP) h);
		} else {
			((ECP2) g).add((ECP2) h);
		}
	}

	public static void pointSubtract(Object g, Object h) {
		if (g instanceof ECP) {
			((ECP) g).sub((ECP) h);
		} else {
			((ECP2) g).sub((ECP2) h);
		}
	}

	public static Object pointMultiply(Object g, BIG a) {
		if (g instanceof ECP) {
			return ((ECP) g).mul(a);
		} else {
			return ((ECP2) g).mul(a);
		}
	}

	public static Object pointInverse(Object g, BIG q) {
		BIG reciprocal = new BIG(1);
		reciprocal.invmodp(q);
		return pointMultiply(g, reciprocal);
	}

	public static FP12 ate(Object g, Object h) {
		if (g instanceof ECP) {
			return PAIR.ate((ECP2) h, (ECP) g);
		} else {
			return PAIR.ate((ECP2) g, (ECP) h);
		}
	}

	public static FP12 ate2(Object g, Object h, Object k, Object l) {
		ECP a, c;
		ECP2 b, d;

		if (g instanceof ECP) {
			a = (ECP) g;
			b = (ECP2) h;
		} else {
			a = (ECP) h;
			b = (ECP2) g;
		}

		if (k instanceof ECP) {
			c = (ECP) k;
			d = (ECP2) l;
		} else {
			c = (ECP) l;
			d = (ECP2) k;
		}

		return PAIR.ate2(b, a, d, c);
	}

	// To and from bytes

	public static byte[] pointToBytes(Object g) {
		byte[] result = new byte[0];

		if (g == null) {
			return result;
		}

		if (g instanceof ECP) {
			result = new byte[_ECPByteLength];
			((ECP) g).toBytes(result, false);
		} else {
			result = new byte[_ECP2ByteLength];
			((ECP2) g).toBytes(result);
		}

		return result;
	}

	public static byte[] fpToBytes(FP12 p) {
		byte[] result = new byte[_FP12ByteLength];
		p.toBytes(result);

		return result;

	}

	public static byte[] bigToBytes(BIG p) {
		byte[] result = new byte[_BIGByteLength];
		p.toBytes(result);

		return result;

	}

	public static Object pointFromBytes(byte[] bytes) throws Exception {
		Object g;

		if (bytes.length == 0) {
			return null;
		}

		if (bytes.length == _ECPByteLength) {
			g = ECP.fromBytes(bytes);
		} else if (bytes.length == _ECP2ByteLength) {
			g = ECP2.fromBytes(bytes);
		} else {
			throw new Exception("length of byte array " + bytes.length + " does not correspond to ECP or ECP2");
		}

		return g;
	}

	// Helpers

	// StringToECPb converts a string to a point on the curve.
	// It does so by hashing the string and using it as an exponent to generator.
	public static Object StringToECPb(String message, boolean first) {
		byte[] bytes = message.getBytes();

		BIG a = sha3(new BIG(ROM.CURVE_Order), bytes);

		if (first) {
			return ECP.generator().mul(a);
		} else {
			return ECP2.generator().mul(a);
		}

	}

	public static FP12 eProduct(eArg... args) {
		FP12 result = null;
		try {

			class eArgNoExp {
				ECP a;
				ECP2 b;
			}

			if (_OptimizeTate) {
				ArrayList<eArgNoExp> pairs = new ArrayList<eArgNoExp>(args.length);
				for (eArg arg : args) {
					if (arg != null) {
						eArgNoExp newArg = new eArgNoExp();
						if (arg.a instanceof ECP) {
							newArg.a = (ECP) arg.a;
							newArg.b = (ECP2) arg.b;
						} else {
							newArg.a = (ECP) arg.b;
							newArg.b = (ECP2) arg.a;
						}

						if (arg.c != null) {
							newArg.a = newArg.a.mul(arg.c);
						}
						pairs.add(newArg);
					}
				}

				for (int i = 0; i < pairs.size(); i += 2) {
					FP12 e;
					if (i == pairs.size() - 1) {
						e = PAIR.ate(pairs.get(i).b, pairs.get(i).a);
					} else {
						e = PAIR.ate2(pairs.get(i).b, pairs.get(i).a, pairs.get(i + 1).b, pairs.get(i + 1).a);
					}
					if (result == null) {
						result = e;
					} else {
						result.mul(e);
					}
				}
				result = PAIR.fexp(result);
			} else {
				for (eArg arg : args) {
					if (arg == null) {
						continue;
					}
					FP12 e;
					if (arg.a instanceof ECP) {
						e = PAIR.fexp(PAIR.ate((ECP2) arg.b, (ECP) arg.a));
					} else {
						e = PAIR.fexp(PAIR.ate((ECP2) arg.a, (ECP) arg.b));
					}

					if (arg.c != null) {
						e = e.pow(arg.c);
					}
					if (result == null) {
						result = e;
					} else {
						result.mul(e);
					}
				}
			}

			return result;
		} catch (Exception e) {
			return result;
		}
	}

	public static BIG sha3(BIG q, byte[] raw) {

		byte[] hash = new byte[32];
		SHA3 sha3 = new SHA3(SHA3.HASH256);

		for (int i = 0; i < raw.length; i++) {
			sha3.process(raw[i]);
		}
		sha3.hash(hash);

		BIG result = BIG.fromBytes(hash);
		result.mod(q);

		return result;
	}

	public static boolean pkEqual(Object first, Object second) {
		return pointEqual(first, second);
	}

	public static boolean verifyKeyPair(BIG sk, Object pk) {

		Object target;
		if (pk instanceof ECP) {
			target = ECP.generator().mul(sk);
		} else {
			target = ECP2.generator().mul(sk);
		}
		return pkEqual(pk, target);

	}

	public static byte[] hashIndices(Index[] indices) {
		ByteArrayOutputStream raw = new ByteArrayOutputStream();

		Index[] d = Arrays.copyOf(indices, indices.length);
		Arrays.sort(d, new Comparator<Index>() {
			@Override
			public int compare(Index self, Index other) {
				if (self.i < other.i || self.j < other.j) {
					return 1;
				} else if (self.i == other.i || self.j == other.j) {
					return 0;
				} else {
					return -1;
				}
			}
		});

		try {
			for (int i = 0; i < d.length; i++) {
				raw.write(ByteBuffer.allocate(4).putInt(d[i].i).array());
				raw.write(ByteBuffer.allocate(4).putInt(d[i].j).array());
				raw.write(pointToBytes(d[i].attribute));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return raw.toByteArray();
	}
}