package org.bouncycastle.crypto.agreement.Owl;

import java.math.BigInteger;

/**
 * The payload sent/received during the optional explicit key confirmation stage of the protocol,
 * <p>
 * Both {@link Owl_Client} and {@link Owl_Server} create and send an instance
 * of this payload to the other.
 * The payload to send should be created via
 * {@link #intitiateKeyConfirmation(BigInteger)}
 * <p>
 * Both {@link Owl_Client} and {@link Owl_Server} must also validate the payload
 * received from the other.
 * The received payload should be validated via
 * {@link #validateKeyConfirmation(Owl_KeyConfirmation, BigInteger)}
 */
public class Owl_KeyConfirmation
{

    /**
     * The id of the {@link ECJPAKEParticipant} who created/sent this payload.
     */
    private final String id;

    /**
     * The value of MacTag, as computed by the key confirmation round.
     *
     * @see Owl_Util#calculateMacTag
     */
    private final BigInteger macTag;

    public Owl_KeyConfirmation(String id, BigInteger magTag)
    {
        this.id = id;
        this.macTag = magTag;
    }

    public String getId()
    {
        return id;
    }

    public BigInteger getMacTag()
    {
        return macTag;
    }

}