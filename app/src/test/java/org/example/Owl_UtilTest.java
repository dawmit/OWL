package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

public class Owl_UtilTest
    extends TestCase
{
    private static final BigInteger ONE = BigInteger.valueOf(1);


    public void testCalculateGA()
        throws CryptoException
    {
        // test gx is infinity

        Owl_Curve curve = Owl_Curves.NIST_P256;

        ECPoint gx1 = Owl_Util.calculateGx(curve.getG(), generateX1());
        ECPoint gx2 = Owl_Util.calculateGx(curve.getG(), generateX1());
        try 
        {
            Owl_Util.calculateGA(gx1, gx2, curve.getCurve().getInfinity());
            fail();
        }
        catch (CryptoException e) {
            // pass
        }
        try 
        {
            Owl_Util.calculateGA(gx1,curve.getCurve().getInfinity(), gx2);
            fail();
        }
        catch (CryptoException e) {
            // pass
        }
        try 
        {
            Owl_Util.calculateGA(curve.getCurve(), gx2, gx1);
            fail();
        }
        catch (CryptoException e) {
            // pass
        }
    }

    public void testValidateParticipantIdsDiffer()
        throws CryptoException
    {
        Owl_Util.validateParticipantIdsDiffer("a", "b");
        Owl_Util.validateParticipantIdsDiffer("a", "A");

        try
        {
            Owl_Util.validateParticipantIdsDiffer("a", "a");
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateParticipantIdsEqual()
        throws CryptoException
    {
        Owl_Util.validateParticipantIdsEqual("a", "a");

        try
        {
            Owl_Util.validateParticipantIdsEqual("a", "b");
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateMacTag()
        throws CryptoException
    {
        ECJPAKECurve curve1 = ECJPAKECurves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest = SHA256Digest.newInstance();

        BigInteger x1 = Owl_Util.generateX1(curve1.getN(), random);
        BigInteger x2 = Owl_Util.generateX1(curve1.getN(), random);
        BigInteger x3 = Owl_Util.generateX1(curve1.getN(), random);
        BigInteger x4 = Owl_Util.generateX1(curve1.getN(), random);

        ECPoint gx1 = Owl_Util.calculateGx(curve1.getG(), x1);
        ECPoint gx2 = Owl_Util.calculateGx(curve1.getG(), x2);
        ECPoint gx3 = Owl_Util.calculateGx(curve1.getG(), x3);
        ECPoint gx4 = Owl_Util.calculateGx(curve1.getG(), x4);

        ECPoint gB = Owl_Util.calculateGA(gx3, gx1, gx2);

        BigInteger s = Owl_Util.calculateS(curve1.getN(), "password".toCharArray());

        BigInteger xs = Owl_Util.calculateX2s(curve1.getN(), x4, s);

        ECPoint B = Owl_Util.calculateA(gB, xs);

        BigInteger keyingMaterial = Owl_Util.calculateKeyingMaterial(curve1.getN(), gx4, x2, s, B);

        BigInteger macTag = Owl_Util.calculateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest);

        Owl_Util.validateMacTag("partnerParticipantId", "participantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);

        // validating own macTag (as opposed to the other party's mactag)
        try
        {
            Owl_Util.validateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // participant ids switched
        try
        {
            Owl_Util.validateMacTag("participantId", "partnerParticipantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);

            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateNotNull()
        throws CryptoException
    {
        Owl_Util.validateNotNull("a", "description");

        try
        {
            Owl_Util.validateNotNull(null, "description");
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }
    }

    public void testValidateR()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        Digest digest  = SHA256Digest.newInstance();
        ECPoint g = curve.getG();
        BigInteger n = curve.getN();
        ECPoint gt = Owl_Util.calculateGx(g, Owl_Util.calculateT(n, "usernameAndPassword", digest));
        ECPoint gx1 = Owl_Util.calculateGx(g, Owl_Util.generateX1());
        BigInteger h = Owl_Util.generateX1();
        //incorrect r
        try 
        {
            Owl_Util.validateR(r, gx1, h, gt, g, n);
            fail();
        }
        catch 
        {
            // pass
        }
    }

    public void testValidateZeroKnowledgeProof()
        throws CryptoException
    {
        ECJPAKECurve curve1 = ECJPAKECurves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest1 = SHA256Digest.newInstance();

        BigInteger x1 = Owl_Util.generateX1(curve1.getN(), random);
        ECPoint gx1 = Owl_Util.calculateGx(curve1.getG(), x1);
        String participantId1 = "participant1";

        ECSchnorrZKP zkp1 = Owl_Util.calculateZeroKnowledgeProof(curve1.getG(), curve1.getN(), x1, gx1, digest1, participantId1, random);

        // should succeed
        Owl_Util.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);

        // wrong group
        ECJPAKECurve curve2 = ECJPAKECurves.NIST_P384;
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve2.getG(), gx1, zkp1, curve2.getQ(), curve2.getN(), curve2.getCurve(), curve2.getH(), participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong digest
        Digest digest2 = new SHA1Digest();
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest2);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong participant
        String participantId2 = "participant2";
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong gx
        BigInteger x2 = Owl_Util.generateX1(curve1.getN(), random);
        ECPoint gx2 = Owl_Util.calculateGx(curve1.getG(), x2);
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), gx2, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }


        // wrong zkp, we need to change the zkp in some way to test if it catches it
        ECSchnorrZKP zkp2 = Owl_Util.calculateZeroKnowledgeProof(curve1.getG(), curve1.getN(), x2, gx2, digest1, participantId1, random);
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp2, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx <= Infinity
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), curve1.getCurve().getInfinity(), zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // (x,y) elements for Gx are not in Fq ie: not in [0,q-1]
        ECCurve.AbstractFp curve = curve1.getCurve();
        try
        {
            ECPoint invalidGx_1 = curve.createPoint(ONE.negate(), ONE);
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), invalidGx_1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }
        try
        {

            ECPoint invalidGx_2 = curve.createPoint(ONE, ONE.negate());
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), invalidGx_2, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }
        try
        {

            ECPoint invalidGx_3 = curve.createPoint(curve1.getQ(), ONE);
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), invalidGx_3, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }
        try
        {
            ECPoint invalidGx_4 = curve.createPoint(ONE, curve1.getQ());
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), invalidGx_4, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }

        // gx is not on the curve
        ECPoint invalidPoint = curve.createPoint(ONE, ONE);//Must come back and test this since (1,1) may exist on certain curves. Not for p256 though.
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), invalidPoint, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        /*  gx is such that n*gx == infinity
         *  Taking gx as any multiple of the generator G will create such a point
         */

        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), curve1.getG(), zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        /*  V is not a point on the curve
         *  i.e. V != G*r + X*h
         */
        try
        {
            Owl_Util.validateZeroKnowledgeProof(curve1.getG(), curve.createPoint(ONE, ONE), zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }
}