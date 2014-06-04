package noconflict.org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

import noconflict.org.bouncycastle.crypto.CryptoException;
import noconflict.org.bouncycastle.crypto.Signer;
import noconflict.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

interface TlsSigner
{
    byte[] calculateRawSignature(SecureRandom random, AsymmetricKeyParameter privateKey, byte[] md5andsha1)
        throws CryptoException;

    Signer createVerifyer(AsymmetricKeyParameter publicKey);

    boolean isValidPublicKey(AsymmetricKeyParameter publicKey);
}
