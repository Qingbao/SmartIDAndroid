package noconflict.org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

import noconflict.org.bouncycastle.crypto.CryptoException;
import noconflict.org.bouncycastle.crypto.Signer;
import noconflict.org.bouncycastle.crypto.digests.NullDigest;
import noconflict.org.bouncycastle.crypto.encodings.PKCS1Encoding;
import noconflict.org.bouncycastle.crypto.engines.RSABlindedEngine;
import noconflict.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import noconflict.org.bouncycastle.crypto.params.ParametersWithRandom;
import noconflict.org.bouncycastle.crypto.params.RSAKeyParameters;
import noconflict.org.bouncycastle.crypto.signers.GenericSigner;

class TlsRSASigner implements TlsSigner
{
    public byte[] calculateRawSignature(SecureRandom random, AsymmetricKeyParameter privateKey, byte[] md5andsha1)
        throws CryptoException
    {
        Signer sig = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), new NullDigest());
        sig.init(true, new ParametersWithRandom(privateKey, random));
        sig.update(md5andsha1, 0, md5andsha1.length);
        return sig.generateSignature();
    }

    public Signer createVerifyer(AsymmetricKeyParameter publicKey)
    {
        Signer s = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), new CombinedHash());
        s.init(false, publicKey);
        return s;
    }

    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof RSAKeyParameters && !publicKey.isPrivate();
    }
}
