package org.example;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent/received during the third pass of an Owl exchange.
 * <p>
 * Each {@link Owl_Client} creates and sends an instance
 * of this payload to the {@link Owl_Server} and verifies the previous payload
 * {@link Owl_AuthenticationServerResponse}.
 * The payload to send should be created via
 * {@link Owl_Client#authenticationFinish(Owl_AuthenticationServerResponse)}.
 * <p>
 * Each {@link Owl_Client} must also validate the payload
 * received from the {@link Owl_Server} this is done by the same function
 * {@link Owl_Client#authenticationFinish(Owl_AuthenticationServerResponse)}.
 */
public class Owl_AuthenticationFinish
{
    /**
     *  Client's unique Id
     */
    private final String clientId;
    /**
     * The value alpha.
     */
    private final ECPoint alpha;

    /**
     * The zero Knowledge proof for alpha.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x2pi.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForAlpha;

    /**
     * The value of r = x1 - t.h mod n
     */
    private final BigInteger r;

    public Owl_AuthenticationFinish(
        String clientId,
        ECPoint alpha,
        ECSchnorrZKP knowledgeProofForAlpha,
        BigInteger r)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(alpha, "alpha");
        Owl_Util.validateNotNull(r, "r");
        Owl_Util.validateNotNull(knowledgeProofForAlpha, "knowledgeProofForAlpha");

        this.clientId = clientId;
        this.knowledgeProofForAlpha = knowledgeProofForAlpha;
        this.alpha = alpha;
        this.r = r;
    }

    public String getClientId()
    {
        return clientId;
    }

    public ECPoint getAlpha()
    {
        return alpha;
    }

    public BigInteger getR()
    {
        return r;
    }

    public ECSchnorrZKP getKnowledgeProofForAlpha()
    {
        return knowledgeProofForAlpha;
    }
}