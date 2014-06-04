package noconflict.org.bouncycastle.crypto.tls;

import noconflict.org.bouncycastle.crypto.DSA;
import noconflict.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import noconflict.org.bouncycastle.crypto.params.ECPublicKeyParameters;
import noconflict.org.bouncycastle.crypto.signers.ECDSASigner;

class TlsECDSASigner extends TlsDSASigner
{
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof ECPublicKeyParameters;
    }

    protected DSA createDSAImpl()
    {
        return new ECDSASigner();
    }
}
