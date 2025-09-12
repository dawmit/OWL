package org.example;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Package protected class containing zero knowledge proof, for an Owl key exchange.
 * <p>
 * This class encapsulates the values involved in the Schnorr
 * zero-knowledge proof used in the Owl protocol.
 */
public class ECSchnorrZKP
{

    /**
     * The value of V = G x [v].
     */
    private final ECPoint V;

    /**
     * The value of r = v - d * c mod n
     */
    private final BigInteger r;

    ECSchnorrZKP(ECPoint V, BigInteger r)
    {
        this.V = V;
        this.r = r;
    }

    /**
     * Returns the commitment (V = G x [v] where G is a base point on the elliptic curve and v is an ephemeral secret)
     */
    public ECPoint getV()
    {
        return V;
    }

    /**
     * Returns the prover's response to the challenge c (r = v - d * c mod n where d is the private key)
     * 
    public BigInteger getr()
    {
        return r;
    }
}
