package hig.no.smartid.service;

import java.security.Provider;

public class SecurityProvider extends Provider{
	
	private static final long serialVersionUID = 4730215537472755382L;

	public SecurityProvider(String name, double version, String info) {
		super(name, version, info);
		
		put("Mac.ISO9797ALG3MAC", "org.bouncycastle.jce.provider.JCEMac$DES9797Alg3");
//      put("Alg.Alias.Mac.ISO9797ALG3", "ISO9797ALG3MAC");
      
      put("Mac.ISO9797ALG3WITHISO7816-4PADDING", "noconflict.org.bouncycastle.jce.provider.JCEMac$DES9797Alg3with7816d4");
//      put("Alg.Alias.Mac.ISO9797ALG3MACWITHISO7816-4PADDING", "ISO9797ALG3WITHISO7816-4PADDING");
      
      put("Signature.SHA1withRSA/ISO9796-2", "noconflict.org.bouncycastle.jce.provider.JDKISOSignature$SHA1WithRSAEncryption");
	}
}
