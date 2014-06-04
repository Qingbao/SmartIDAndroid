package noconflict.org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

import noconflict.org.bouncycastle.crypto.CipherKeyGenerator;
import noconflict.org.bouncycastle.crypto.engines.CAST6Engine;
import noconflict.org.bouncycastle.jce.provider.JCEBlockCipher;
import noconflict.org.bouncycastle.jce.provider.JCEKeyGenerator;

public final class CAST6
{
    private CAST6()
    {
    }
    
    public static class ECB
        extends JCEBlockCipher
    {
        public ECB()
        {
            super(new CAST6Engine());
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("CAST6", 256, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.CAST6", "org.bouncycastle.jce.provider.symmetric.CAST6$ECB");
            put("KeyGenerator.CAST6", "org.bouncycastle.jce.provider.symmetric.CAST6$KeyGen");
        }
    }
}
