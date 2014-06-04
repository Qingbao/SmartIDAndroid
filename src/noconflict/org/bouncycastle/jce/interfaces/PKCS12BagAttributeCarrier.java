package noconflict.org.bouncycastle.jce.interfaces;

import java.util.Enumeration;

import noconflict.org.bouncycastle.asn1.DEREncodable;
import noconflict.org.bouncycastle.asn1.DERObjectIdentifier;

/**
 * allow us to set attributes on objects that can go into a PKCS12 store.
 */
public interface PKCS12BagAttributeCarrier
{
    void setBagAttribute(
        DERObjectIdentifier oid,
        DEREncodable        attribute);

    DEREncodable getBagAttribute(
        DERObjectIdentifier oid);

    Enumeration getBagAttributeKeys();
}
