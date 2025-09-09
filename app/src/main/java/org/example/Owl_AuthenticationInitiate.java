package org.example;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent by the client in the authenticaion first pass by {@link Owl_Client}
 * <p>
 * Each {@link Owl_Client} creates and sends an instance
 * of this payload to the {@link Owl_Server}.
 * The payload to send should be created via
 * {@link Owl_Client#authenticationInitiate()}.
 */
public class Owl_AuthenticationInitiate
{

    /**
     * Unique identifier for the client (this is the username)
     * <p>
     * ClientId must not be the same as the server unique identifier,
     * </p>
     */
    private final String clientId;

    /**
     * The value of g^x1
     */
    private final ECPoint gx1;

    /**
     * The value of g^x2
     */
    private final ECPoint gx2;

    /**
     * The zero knowledge proof for x1.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x1.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX1;

    /**
     * The zero knowledge proof for x2.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x2.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX2;

    public Owl_AuthenticationInitiate(
        String clientId,
        ECPoint gx1,
        ECPoint gx2,
        ECSchnorrZKP knowledgeProofForX1,
        ECSchnorrZKP knowledgeProofForX2)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(gx1, "gx1");
        Owl_Util.validateNotNull(gx2, "gx2");
        Owl_Util.validateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
        Owl_Util.validateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

        this.clientId = clientId;
        this.gx1 = gx1;
        this.gx2 = gx2;
        this.knowledgeProofForX1 = knowledgeProofForX1;
        this.knowledgeProofForX2 = knowledgeProofForX2;
    }

    public String getClientId()
    {
        return clientId;
    }

    public ECPoint getGx1()
    {
        return gx1;
    }

    public ECPoint getGx2()
    {
        return gx2;
    }

    public ECSchnorrZKP getKnowledgeProofForX1()
    {
        return knowledgeProofForX1;
    }

    public ECSchnorrZKP getKnowledgeProofForX2()
    {
        return knowledgeProofForX2;
    }

}