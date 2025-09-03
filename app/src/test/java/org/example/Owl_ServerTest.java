package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Owl_ServerTest
{
    @Test
    public void testConstruction()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String serverId = "serverId";
        char[] password = "password".toCharArray();

    // should succeed
    assertDoesNotThrow(() -> new Owl_Server(serverId, password, curve, digest, random));

    // null serverId
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(null, password, curve, digest, random));

    // null password
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(serverId, null, curve, digest, random));

    // empty password
    assertThrows(IllegalArgumentException.class,
        () -> new Owl_Server(serverId, "".toCharArray(), curve, digest, random));

    // null curve
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(serverId, password, null, digest, random));

    // null digest
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(serverId, password, curve, null, random));

    // null random
    assertThrows(NullPointerException.class,
        () -> new Owl_Server(serverId, password, curve, digest, null));
    }

    @Test
    public void testSuccessfulExchange()
        throws CryptoException
    {

        Owl_Server server = createServer();
        Owl_Client client = createClient();

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        server.authenticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);

        assertEquals(serverKeyingMaterial, clientKeyingMaterial);

    }

    @Test
    public void testIncorrectPassword()
        throws CryptoException
    {
        Owl_Server server = createServer();
        Owl_Client client = createClientWithWrongPassword();

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        server.authenticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        // Validate incorrect passwords result in a CryptoException
        assertThrows(CryptoException.class, () -> client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial));

        assertThrows(CryptoException.class, () -> server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial));
    }

    @Test
    public void testStateValidation() throws CryptoException {
        Owl_Server server = createServer();
        Owl_Client client = createClient();

        // START USER LOGIN REGISTRATION CHECKS
        assertEquals(Owl_Server.REGISTRATION_NOT_CALLED, server.getRegistrationState());

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUseronServer(clientRegistrationPayload);

        // create server registration payload twice should fail
        assertThrows(IllegalStateException.class, () -> server.registerUseronServer(clientRegistrationPayload));

        // START LOGIN INITIALISATION CHECKS
        assertEquals(Owl_Server.STATE_INITIALISED, server.getState());

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();

        // call server login end before login response should fail
        assertThrows(IllegalStateException.class, () -> server.authenticationServerEnd(null));

        Owl_AuthenticationServerResponse serverLoginResponsePayload =
            assertDoesNotThrow(() -> server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload));

        assertEquals(Owl_Server.STATE_LOGIN_INITIALISED, server.getState());

        // create server login response twice should fail
        assertThrows(IllegalStateException.class, () ->
            server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload));

        Owl_AuthenticationFinish clientLoginFinishPayload =
            assertDoesNotThrow(() -> client.authenticationFinish(serverLoginResponsePayload));

        // START LOGIN FINISH CHECKS
        assertThrows(IllegalStateException.class, server::calculateKeyingMaterial);

        assertDoesNotThrow(() -> server.authenticationServerEnd(clientLoginFinishPayload));
        assertEquals(Owl_Server.STATE_LOGIN_FINISHED, server.getState());

        // create server login end twice should fail
        assertThrows(IllegalStateException.class, () -> server.authenticationServerEnd(clientLoginFinishPayload));

        // START KEY CALCULATION CHECKS
        assertThrows(IllegalStateException.class, () -> server.initiateKeyConfirmation(null));

        BigInteger rawServerKey = assertDoesNotThrow(server::calculateKeyingMaterial);
        assertEquals(Owl_Server.STATE_KEY_CALCULATED, server.getState());

        assertThrows(IllegalStateException.class, server::calculateKeyingMaterial);

        BigInteger rawClientKey = assertDoesNotThrow(client::calculateKeyingMaterial);

        // START KEY CONFIRMATION CHECKS
        assertThrows(IllegalStateException.class, () -> server.validateKeyConfirmation(null, rawServerKey));

        Owl_KeyConfirmation serverKC = assertDoesNotThrow(() -> server.initiateKeyConfirmation(rawServerKey));
        assertEquals(Owl_Server.STATE_KC_INITIALISED, server.getState());

        assertThrows(IllegalStateException.class, () -> server.initiateKeyConfirmation(null));

        Owl_KeyConfirmation clientKC = assertDoesNotThrow(() -> client.initiateKeyConfirmation(rawClientKey));

        assertDoesNotThrow(() -> server.validateKeyConfirmation(clientKC, rawServerKey));
        assertEquals(Owl_Server.STATE_KC_VALIDATED, server.getState());

        assertDoesNotThrow(() -> client.validateKeyConfirmation(serverKC, rawClientKey));
    }

    @Test
    public void testAuthenticationServerResponse() throws CryptoException {
        Owl_Curve curve = Owl_Curves.NIST_P256;

        // Setup
        Owl_InitialRegistration clientRegistrationPayload = createClient().initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = createServer().registerUseronServer(clientRegistrationPayload);
        Owl_AuthenticationInitiate clientAuthInit = createClient().authenticationInitiate();

        // Should work
        assertDoesNotThrow(() -> createServer().authenticationServerResponse(clientAuthInit, serverRegistrationPayload));

        // serverId and clientId are the same
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    "server",
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // g^x1 = infinity
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    curve.getCurve().getInfinity(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // g^x2 = infinity
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    curve.getCurve().getInfinity(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // zero knowledge proof for x1 fails
        Owl_AuthenticationInitiate clientAuthInit2 = createClient().authenticationInitiate();
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit2.getKnowledgeProofForX1(),
                    clientAuthInit.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // zero knowledge proof for x2 fails
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                new Owl_AuthenticationInitiate(
                    clientAuthInit.getClientId(),
                    clientAuthInit.getGx1(),
                    clientAuthInit.getGx2(),
                    clientAuthInit.getKnowledgeProofForX1(),
                    clientAuthInit2.getKnowledgeProofForX2()
                ),
                serverRegistrationPayload
            )
        );

        // clientId mismatch between payload and server registration
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerResponse(
                clientAuthInit,
                new Owl_FinishRegistration(
                    "server",
                    serverRegistrationPayload.getKnowledgeProofForX3(),
                    serverRegistrationPayload.getGx3(),
                    serverRegistrationPayload.getPi(),
                    serverRegistrationPayload.getGt()
                )
            )
        );
    }

    @Test
    public void testAuthenticationServerEnd() throws CryptoException {
        Owl_AuthenticationFinish clientLoginFinishPayload = runExchangeUntilPass3();
        Owl_Server server = createServer();

        // should succeed
        assertDoesNotThrow(() -> server.authenticationServerEnd(clientLoginFinishPayload));

        // clientId is the same as serverId
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                "server",
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()
            ))
        );

        // clientId mismatch
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                "client2",
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()
            ))
        );

        // validation fails: incorrect alpha
        Owl_AuthenticationFinish clientLoginFinishPayload2 = runExchangeUntilPass3();
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload2.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()
            ))
        );

        // validation fails: incorrect knowledge proof for alpha
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()
            ))
        );

        // validation fails: incorrect r value
        assertThrows(CryptoException.class, () ->
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload2.getR()
            ))
        );
    }

    private Owl_Server createServer()
    {
        return new Owl_Server("server", "password".toCharArray(), Owl_Curves.NIST_P256);
    }

    private Owl_Client createClient()
    {
        return new Owl_Client("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }

    private Owl_Client createClientWithWrongPassword()
    {
        return new Owl_Client("client", "wrong".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_AuthenticationFinish runExchangeUntilPass3()
    throws CryptoException
    {
        Owl_Server server = createServer();
        Owl_Client client = createClient();

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        return client.authenticationFinish(serverLoginResponsePayload);
    }
}