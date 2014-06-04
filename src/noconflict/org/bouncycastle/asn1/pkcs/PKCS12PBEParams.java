package noconflict.org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;

import noconflict.org.bouncycastle.asn1.ASN1Encodable;
import noconflict.org.bouncycastle.asn1.ASN1EncodableVector;
import noconflict.org.bouncycastle.asn1.ASN1OctetString;
import noconflict.org.bouncycastle.asn1.ASN1Sequence;
import noconflict.org.bouncycastle.asn1.DERInteger;
import noconflict.org.bouncycastle.asn1.DERObject;
import noconflict.org.bouncycastle.asn1.DEROctetString;
import noconflict.org.bouncycastle.asn1.DERSequence;

public class PKCS12PBEParams
    extends ASN1Encodable
{
    DERInteger      iterations;
    ASN1OctetString iv;

    public PKCS12PBEParams(
        byte[]      salt,
        int         iterations)
    {
        this.iv = new DEROctetString(salt);
        this.iterations = new DERInteger(iterations);
    }

    public PKCS12PBEParams(
        ASN1Sequence  seq)
    {
        iv = (ASN1OctetString)seq.getObjectAt(0);
        iterations = (DERInteger)seq.getObjectAt(1);
    }

    public static PKCS12PBEParams getInstance(
        Object  obj)
    {
        if (obj instanceof PKCS12PBEParams)
        {
            return (PKCS12PBEParams)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new PKCS12PBEParams((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public BigInteger getIterations()
    {
        return iterations.getValue();
    }

    public byte[] getIV()
    {
        return iv.getOctets();
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(iv);
        v.add(iterations);

        return new DERSequence(v);
    }
}
