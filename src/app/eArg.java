package app;

import org.apache.milagro.amcl.FP256BN.BIG;

class eArg {
	Object a;
	Object b;
	BIG c;
	
	public eArg(Object a, Object b, BIG c) {
		this.a = a;
		this.b = b;
		this.c = c;
	}
}