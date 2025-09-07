package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class Owl_ServerRegistration
{
   /*
     * Possible state for user registration.
     */
    public static final boolean REGISTRATION_NOT_CALLED = false;
    public static final boolean REGISTRATION_CALLED = true;
    /**
     * Unique identifier of this server.
     * The client and server in the exchange must NOT share the same id.
     */
    private final String serverId;
    /**
     * Digest to use during calculations.
     */
    private final Digest digest;

    /**
     * Source of secure random data.
     */
    private final SecureRandom random;
    
    private BigInteger n;
    private ECPoint g;
    /**
     * Checks if user registration is called more than once.
     */
    private boolean registrationState;
    /**
     * Check's the status of the user registration
     * I.E. whether or not this server has registered a user already.
     * See the <tt>REGSITRATION_*</tt> constants for possible values.
     */

    public boolean getRegistrationState()
    {
        return this.registrationState;
    }
    /**
     * Convenience constructor for a new {@link Owl_ServerRegistration} that uses
     * the {@link Owl_Curves#NIST_P256} elliptic curve,
     * a SHA-256 digest, and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALISED}.
     *
     * @param serverId unique identifier of this server.
     *                      The server and client in the exchange must NOT share the same id.
     * @throws NullPointerException     if any argument is null
     */
    public Owl_ServerRegistration(
        String serverId)
    {
        this(
            serverId,
            Owl_Curves.NIST_P256);
    }

    /**
     * Convenience constructor for a new {@link Owl_ServerRegistration} that uses
     * a SHA-256 digest and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALISED}.
     *
     * @param serverId unique identifier of this server.
     *                      The server and client in the exchange must NOT share the same id.
     * @param curve         elliptic curve
     *                      See {@link Owl_Curves} for standard curves.
     * @throws NullPointerException     if any argument is null
     */
    public Owl_ServerRegistration(
        String serverId,
        Owl_Curve curve)
    {
        this(
            serverId,
            curve,
            SHA256Digest.newInstance(),
            CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Construct a new {@link Owl_ServerRegistration}.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALISED}.
     *
     * @param serverId unique identifier of this server.
     *                      The client and server in the exchange must NOT share the same id.
     *                      See {@link Owl_Curves} for standard curves
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x3 and x4, and for the zero knowledge proofs
     * @throws NullPointerException     if any argument is null
     */
    public Owl_ServerRegistration(
        String serverId,
        Owl_Curve curve,
        Digest digest,
        SecureRandom random)
    {
        Owl_Util.validateNotNull(serverId, "serverId");
        Owl_Util.validateNotNull(curve, "curve params");
        Owl_Util.validateNotNull(digest, "digest");
        Owl_Util.validateNotNull(random, "random");

        this.serverId = serverId;
        this.g = curve.getG();
        this.n = curve.getN();

        this.digest = digest;
        this.random = random;

        this.registrationState = REGISTRATION_NOT_CALLED;
    }
    /**
     * Initiates user registration with the server. Creates the registration payload {@link Owl_InitialRegistration} and sends it to the server.
     * MUST be sent over a secure channel.
     * <p>
     * Must be called prior to {@link #registerUseronServer(Owl_InitialRegistration)}
     * @throws IllegalStateException if this function is called more than once
     */

    /**
     * Recieves the payload sent by the client as part of user registration, and stores necessary values away in the server (upto the user of this protocol).
     * <p>
     * Must be called after {@link #initiateUserRegistration()} by the {@link Owl_Client}.
     * @throws IllegalStateException if this functions is called more than once.
     */
    public Owl_FinishRegistration registerUseronServer(
        Owl_InitialRegistration userLoginRegistrationReceived
        )
    {
        if(this.registrationState)
        {
            throw new IllegalStateException("Server has already registrered this payload, by "+ serverId);
        }
        BigInteger x3 = Owl_Util.generateX1(n, random);

        ECPoint gx3 = Owl_Util.calculateGx(g, x3);

        ECSchnorrZKP knowledgeProofForX3 = Owl_Util.calculateZeroknowledgeProof(g, n, x3, gx3, digest, serverId, random);

        String clientId = userLoginRegistrationReceived.getClientId();
        BigInteger pi = userLoginRegistrationReceived.getPi();
        ECPoint gt = userLoginRegistrationReceived.getGt();

        this.registrationState = REGISTRATION_CALLED;

        return new Owl_FinishRegistration(clientId, knowledgeProofForX3, gx3, pi, gt); 
    }
}