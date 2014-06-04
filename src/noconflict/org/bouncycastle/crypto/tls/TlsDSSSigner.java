package noconflict.org.bouncycastle.crypto.tls;

import noconflict.org.bouncycastle.crypto.DSA;
import noconflict.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import noconflict.org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import noconflict.org.bouncycastle.crypto.signers.DSASigner;

class TlsDSSSigner extends TlsDSASigner
{
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof DSAPublicKeyParameters;
    }

    protected DSA createDSAImpl()
    {
        return new DSASigner();
    }
}
