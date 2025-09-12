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
/**
 * A server in the Owl PAKE protocol specifically for the user registration phase.
 * <p>
 * The Owl exchange is defined by Feng Hao and Peter Ryan in the paper
 * <a href="https://eprint.iacr.org/2023/768.pdf">
 * "Owl: An Augmented Password-Authenticated Key Exchange Scheme"</a>
 * <p>
 * The Owl protocol is asymmetric.
 * There is one client and one server communicating between each other.
 * An instance of {@link Owl_ServerRegistration} represents one server, and
 * an instance of {@link Owl_ClientRegistration} represents one client.
 * These together make up the main machine through which user registration is facilitated.
 * <p>
 * To execute the registration, construct an {@link Owl_ServerRegistration} on the server end,
 * and construct an {@link Owl_ClientRegistration} on the client end.
 * Each Owl registration will need a new and distinct {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration}.
 * You cannot use the same {@link Owl_ServerRegistration} or {@link Owl_ClientRegistration} for multiple exchanges.
 * There are three distinct actions that can be taken: user registration - where the client registers
 * as a new user on the server; login - where an existing user (client) attempts to login and the Owl protocol authenticates this
 * exchange; and password update - where the user (client) can update their password.
 * <p>
 * For user login go to {@link Owl_Client} and {@link Owl_Server}.
 * To execute the user registration phase, both
 * {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration} must be constructed. 
 * <p>
 * The following communication between {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration}, must be
 * facilitated over a secure communications channel as the leakage of the payload sent, 
 * would allow an attacker to reconstruct the secret password.
 * <p>
 * Call the following methods in this order, the client initiates every exchange:
 * <ul>
 *   <li>{@link Owl_ClientRegistration#initiateUserRegistration()} - send payload to the server over a secure channel.</li>
 *   <li>{@link Owl_ServerRegistration#registerUseronServer(Owl_InitialRegistration)} - use the payload received from the client to calculate a secret payload that is to be safely stored by the user of this protocol.</li>
 * </ul>
 * <p>
 * This class is stateful and NOT threadsafe.
 * Each instance should only be used for ONE complete Owl exchange
 * (i.e. a new {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration} should be constructed for each new Owl exchange).
 */
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
     * See the <code>REGSITRATION_*</code> constants for possible values.
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
     * After construction, the {@link #getRegistrationState() registrationState} will be  {@link #REGISTRATION_NOT_CALLED}.
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
     * After construction, the {@link #getRegistrationState() registrationState} will be  {@link #REGISTRATION_NOT_CALLED}.
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
     * After construction, the {@link #getRegistrationState() registrationState} will be  {@link #REGISTRATION_NOT_CALLED}.
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
     * Must be called after {@link Owl_ClientRegistration#initiateUserRegistration()} by the {@link Owl_Client}.
     * @throws IllegalStateException if this functions is called more than once.
     */
    public Owl_FinishRegistration registerUseronServer(
        Owl_InitialRegistration userLoginRegistrationReceived
        )
    throws CryptoException
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

        Owl_Util.validateParticipantIdsDiffer(clientId, serverId);
        if (pi.compareTo(BigInteger.ONE)==-1 || pi.compareTo(n.subtract(BigInteger.ONE)) == 1) {
            throw new CryptoException("pi is not in the range of [1, n-1]. for " + serverId); 
        }
        this.registrationState = REGISTRATION_CALLED;

        return new Owl_FinishRegistration(clientId, knowledgeProofForX3, gx3, pi, gt); 
    }
}