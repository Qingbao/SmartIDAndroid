package noconflict.org.bouncycastle.asn1.ocsp;

import noconflict.org.bouncycastle.asn1.ASN1Encodable;
import noconflict.org.bouncycastle.asn1.ASN1EncodableVector;
import noconflict.org.bouncycastle.asn1.DERObject;
import noconflict.org.bouncycastle.asn1.DERSequence;
import noconflict.org.bouncycastle.asn1.x500.X500Name;

public class ServiceLocator
    extends ASN1Encodable
{
    X500Name    issuer;
    DERObject    locator;

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * ServiceLocator ::= SEQUENCE {
     *     issuer    Name,
     *     locator   AuthorityInfoAccessSyntax OPTIONAL }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(issuer);

        if (locator != null)
        {
            v.add(locator);
        }

        return new DERSequence(v);
    }
}
