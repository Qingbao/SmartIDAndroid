package noconflict.org.bouncycastle.jce.provider.symmetric;

import java.util.HashMap;

import noconflict.org.bouncycastle.crypto.CipherKeyGenerator;
import noconflict.org.bouncycastle.crypto.engines.Salsa20Engine;
import noconflict.org.bouncycastle.jce.provider.JCEKeyGenerator;
import noconflict.org.bouncycastle.jce.provider.JCEStreamCipher;

public final class Salsa20
{
    private Salsa20()
    {
    }
    
    public static class Base
        extends JCEStreamCipher
    {
        public Base()
        {
            super(new Salsa20Engine(), 8);
        }
    }

    public static class KeyGen
        extends JCEKeyGenerator
    {
        public KeyGen()
        {
            super("Salsa20", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("Cipher.SALSA20", "org.bouncycastle.jce.provider.symmetric.Salsa20$Base");
            put("KeyGenerator.SALSA20", "org.bouncycastle.jce.provider.symmetric.Salsa20$KeyGen");
        }
    }
}
