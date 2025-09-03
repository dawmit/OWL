package org.example;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent/received during the user login registration of a Owl exchange.
 * <p>
 * Each {@link Owl_Server} creates and sends an instance
 * of this payload to the {@link Owl_Client}.
 * The payload to send should be created via
 * {@link Owl_Server#registerUseronServer(Owl_InitialRegistration)}.
 * <p>
 * The created payload shou;d be securely stored on the server.
 */
public class Owl_FinishRegistration
{

    private final String clientId;

    /**
     * The value g^x3.
     */
    private final ECPoint gx3;

    /**
     * The zero knowledge proof for x3.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x3.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX3;

    /**
     * The value of pi = H(t), where t = H(Username||password) mod(n)
     */
    private final BigInteger pi;

    /**
     * The value of T = g^t
     */
    private final ECPoint gt;



    public Owl_FinishRegistration(
        String clientId,
        ECSchnorrZKP knowledgeProofForX3,
        ECPoint gx3,
        BigInteger pi,
        ECPoint gt)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(pi, "pi");
        Owl_Util.validateNotNull(gt, "gt");
        Owl_Util.validateNotNull(gx3, "gx3");
        Owl_Util.validateNotNull(knowledgeProofForX3, "knowledgeProofForX3");

        this.clientId = clientId;
        this.knowledgeProofForX3 = knowledgeProofForX3;
        this. gx3 = gx3;
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

    public ECPoint getGx3()
    {
        return gx3;
    }

    public ECSchnorrZKP getKnowledgeProofForX3()
    {
        return knowledgeProofForX3;
    }
}