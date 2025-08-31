package org.bouncycastle.crypto.agreement.Owl;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent/received during the user login registration stage of an Owl exchange.
 * <p>
 * The {@link Owl_Client} creates and sends an instance
 * of this payload to the {@link Owl_Server}.
 * The payload to send should be created via
 * {@link Owl_Client#initiateUserRegistration()}.
 * <p>
 * Each {@link Owl_Server} must also validate the payload
 * received from the {@link Owl_Client}.
 * The received payload should be validated via
 * {@link Owl_Server#registerUseronServer(Owl_InitialRegistration)}.
 */
public class Owl_InitialRegistration
{

    private final String clientId;

    /**
     * The value of pi = H(t), where t = H(Username||password) mod(n)
     */
    private final BigInteger pi;

    /**
     * The value of T = g^t
     */
    private final ECPoint gt



    public Owl_InitialRegistration(
        String clientId,
        BigInteger pi,
        ECPoint gt)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(pi, "pi");
        Owl_Util.validateNotNull(gt, "gt");

        this.clientId = clientId;
        this.pi = pi;
        this.gt = gt;
    }

    public String getClientId()
    {
        return clientId;
    }

    public BigInteger getPi()
    {
        return pi;
    }

    public ECPoint getGt()
    {
        return gt;
    }
}