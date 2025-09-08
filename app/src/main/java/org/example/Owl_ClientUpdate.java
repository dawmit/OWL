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

public class Owl_ClientUpdate{
    /*
     * Possible state for user registration.
     */
    public static final boolean UPDATE_NOT_CALLED = false;
    public static final boolean UPDATE_CALLED = true;
    /**
     * Unique identifier of this client.
     * The client and server in the exchange must NOT share the same id.
     */
    private final String clientId;
    /**
     * Shared secret.  This only contains the secret between construction
     * and the call to {@link #initiateUserRegistration()}.
     * <p>
     * i.e. When {@link #initiateUserRegistration()} is called, this buffer overwritten with 0's,
     * and the field is set to null.
     * </p>
     */
    private char[] password;
    /**
     * Shared secret.  This only contains the secret between construction
     * and the call to {@link #initiateUserRegistration()}.
     * <p>
     * i.e. When {@link #initiateUserRegistration()} is called, this buffer overwritten with 0's,
     * and the field is set to null.
     * </p>
     */
    private char[] newPassword;
    /**
     * Digest to use during calculations.
     */
    private final Digest digest;

    /**
     * Source of secure random data.
     */
    private final SecureRandom random;
    /**
     * Client's user specified secret t = H(username||password) mod n
     */
    private BigInteger t;
    
    private BigInteger n;
    private ECPoint g;
    /**
     * Checks if user update is called more than once.
     */
    private boolean updateState;
    /**
     * Check's the status of the user registration
     * I.E. whether or not this server has registered a user already.
     * See the <tt>UPDATE_*</tt> constants for possible values.
     */
    public boolean getUpdateState()
    {
        return this.updateState;
    }

    /**
     * Convenience constructor for a new {@link Owl_ClientUpdate} that uses
     * the {@link Owl_Curves#NIST_P256} elliptic curve,
     * a SHA-256 digest, and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALISED}.
     *
     * @param clientId unique identifier of this client.
     *                      The server and client in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param newPassword   shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Owl_ClientUpdate(
        String clientId,
        char[] password,
        char[] newPassword)
    {
        this(
            clientId,
            password,
            newPassword,
            Owl_Curves.NIST_P256);
    }

    /**
     * Convenience constructor for a new {@link Owl_ClientUpdate} that uses
     * a SHA-256 digest and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALISED}.
     *
     * @param clientId unique identifier of this client..
     *                      The server and client in the exchange must NOT share the same id.     
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param newPassword   shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param curve         elliptic curve
     *                      See {@link Owl_Curves} for standard curves.
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Owl_ClientUpdate(
        String clientId,
        char[] password,
        char[] newPassword,
        Owl_Curve curve)
    {
        this(
            clientId,
            password,
            newPassword,
            curve,
            SHA256Digest.newInstance(),
            CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Construct a new {@link Owl_ClientUpdate}.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALISED}.
     *
     * @param clientId unique identifier of this client.
     *                      The server and client in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param newPassword   shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param curve         elliptic curve.
     *                      See {@link Owl_Curves} for standard curves
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x1 and x2, and for the zero knowledge proofs
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Owl_ClientUpdate(
        String clientId,
        char[] password,
        char[] newPassword,
        Owl_Curve curve,
        Digest digest,
        SecureRandom random)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(password, "password");
        Owl_Util.validateNotNull(newPassword, "new password");
        Owl_Util.validateNotNull(curve, "curve params");
        Owl_Util.validateNotNull(digest, "digest");
        Owl_Util.validateNotNull(random, "random");
        if (password.length == 0)
        {
            throw new IllegalArgumentException("Password must not be empty.");
        }
        if (newPassword.length ==0)
        {
            throw new IllegalArgumentException("New password must not be empty.");
        }

        this.clientId = clientId;

        /*
         * Create a defensive copy so as to fully encapsulate the password.
         *
         * This array will contain the password for the lifetime of this
         * client BEFORE {@link #calculateKeyingMaterial()} is called.
         *
         * i.e. When {@link #calculateKeyingMaterial()} is called, the array will be cleared
         * in order to remove the password from memory.
         *
         * The caller is responsible for clearing the original password array
         * given as input to this constructor.
         */
        this.password = Arrays.copyOf(password, password.length);
        this.newPassword = Arrays.copyOf(newPassword, newPassword.length);
        this.g = curve.getG();
        this.n = curve.getN();

        this.digest = digest;
        this.random = random;

        this.updateState = UPDATE_NOT_CALLED;
    }
    /**
     * Initiates user registration with the server. Creates the registration payload {@link Owl_InitialRegistration} and sends it to the server.
     * MUST be sent over a secure channel.
     * <p>
     * Must be called prior to {@link #registerUseronServer(Owl_InitialRegistration)}
     * @throws IllegalStateException if this function is called more than once
     */
    public Owl_InitialRegistration initiatePasswordUpdate()
    {
        if(this.updateState)
        {
            throw new IllegalStateException("Password update already begun by "+ clientId);
        }
        this.t = calculateT();

        BigInteger pi = calculatePi();

        ECPoint gt = Owl_Util.calculateGx(g, t);

        /*
         * Clear the password array from memory, since we don't need it anymore.
         *
         * Also set the field to null as a flag to indicate that the key has already been calculated.
         */
        Arrays.fill(password, (char)0);
        this.password = null;
        Arrays.fill(newPassword, (char)0);
        this.newPassword = null;
        
        this.updateState = UPDATE_CALLED;

        return new Owl_InitialRegistration(clientId, pi, gt);
    }

    private BigInteger calculateT()
    {
        try 
        {
            return Owl_Util.calculateT(n, clientId + new String(password), digest);
        } 
        catch (CryptoException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }
    private BigInteger calculatePi()
    {
        try 
        {
            return Owl_Util.calculatePi(n, t, digest);
        }
        catch (CryptoException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }
}