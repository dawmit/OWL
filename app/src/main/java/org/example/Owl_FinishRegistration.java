package org.example;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The final payload sent by the {@link Owl_ServerRegistration} during the user registration of a Owl exchange.
 * This payload is to be stored securely by the server.
 * <p>
 * Each {@link Owl_ServerRegistration} creates and sends an instance
 * of this payload ot be stored securely.
 * The payload to send should be created via
 * {@link Owl_ServerRegistration#registerUseronServer(Owl_InitialRegistration)}.
 */
public class Owl_FinishRegistration
{
    /**
     * Unique identifier for the client in this registration phase.
     * <p>
     * Must be different to the server's unique identifier.
     * </p>
     */
    private final String clientId;

    /**
     * The value x3 * [G].
     */
    private final ECPoint gx3;

    /**
     * The zero knowledge proof for x3.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {v*[G], r} for x3.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX3;

    /**
     * The value of pi = H(t), where t = H(Username||password) mod(n)
     */
    private final BigInteger pi;

    /**
     * The value of T = t * [G]
     */
    private final ECPoint gt;

    /**
     * Constructor of Owl_FinishRegistration
     * @param clientId The client identity (or username)
     * @param knowledgeProofForX3 The zero-knowledge proof for the knowledge of x3 for X3
     * @param gx3 The public key X3= [G] * x3
     * @param pi pi = H(t) where t=H(username || password) mod n
     * @param gt T = t * [G]
     */
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
