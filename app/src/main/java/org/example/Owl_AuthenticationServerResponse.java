package org.example;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent/received during the second pass of an Owl exchange.
 * <p>
 * Each {@link Owl_Server} creates and sends an instance
 * of this payload to the {@link Owl_Client}.
 * The payload to send should be created via
 * {@link Owl_Server#authenticationServerResponse(Owl_AuthenticationInitiate, Owl_FinishRegistration)}.
 * <p>
 * Each {@link Owl_Server} must also validate the payload
 * received from the {@link Owl_Client}.
 * The {@link Owl_Server} must retreive the {@link Owl_FinishRegistration} 
 * from wherever the server securely stored the intitial login information.
 * The received payload should be validated via the same function (in the same call).
 */
public class Owl_AuthenticationServerResponse
{

    private final String serverId;

    /**
     * The value of g^x3
     */
    private final ECPoint gx3;

    /**
     * The value of g^x4
     */
    private final ECPoint gx4;

    /**
     * The zero knowledge proof for x3.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x3.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX3;

    /**
     * The zero knowledge proof for x4.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x4.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX4;

    /**
     * The value for beta = (X1 + X2 + X3)^x4pi
     */
    private final ECPoint beta;

    /**
     * The zero knowledge proof for beta.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x4pi.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForBeta;

    public Owl_AuthenticationServerResponse(
        String serverId,
        ECPoint gx3,
        ECPoint gx4,
        ECSchnorrZKP knowledgeProofForX3,
        ECSchnorrZKP knowledgeProofForX4,
        ECPoint beta,
        ECSchnorrZKP knowledgeProofForBeta)
    {
        Owl_Util.validateNotNull(serverId, "serverId");
        Owl_Util.validateNotNull(gx3, "gx3");
        Owl_Util.validateNotNull(gx4, "gx4");
        Owl_Util.validateNotNull(knowledgeProofForX3, "knowledgeProofForX3");
        Owl_Util.validateNotNull(knowledgeProofForX4, "knowledgeProofForX4");
        Owl_Util.validateNotNull(beta, "beta");
        Owl_Util.validateNotNull(knowledgeProofForBeta, "knowledgeProofForBeta");

        this.serverId = serverId;
        this.gx3 = gx3;
        this.gx4 = gx4;
        this.knowledgeProofForX3 = knowledgeProofForX3;
        this.knowledgeProofForX4 = knowledgeProofForX4;
        this.beta = beta;
        this.knowledgeProofForBeta = knowledgeProofForBeta;
    }

    public String getServerId()
    {
        return serverId;
    }

    public ECPoint getGx3()
    {
        return gx3;
    }

    public ECPoint getGx4()
    {
        return gx4;
    }

    public ECSchnorrZKP getKnowledgeProofForX3()
    {
        return knowledgeProofForX3;
    }

    public ECSchnorrZKP getKnowledgeProofForX4()
    {
        return knowledgeProofForX4;
    }

    public ECPoint getBeta()
    {
        return beta;
    }

    public ECSchnorrZKP getKnowledgeProofForBeta()
    {
        return knowledgeProofForBeta;
    }

}