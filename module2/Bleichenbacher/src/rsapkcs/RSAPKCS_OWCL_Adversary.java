package rsapkcs;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

import static utils.NumberUtils.getRandomBigInteger;
import static utils.NumberUtils.ceilDivide;
import static utils.NumberUtils.getCeilLog;

public class RSAPKCS_OWCL_Adversary implements I_RSAPKCS_OWCL_Adversary {
    public RSAPKCS_OWCL_Adversary() {
        // Do not change this constructor!
    }

    /*
     * @see basics.IAdversary#run(basics.IChallenger)
     */
    @Override
    public BigInteger run(final I_RSAPKCS_OWCL_Challenger challenger) {
        BigInteger ciphertext = challenger.getChallenge();
        RSAPKCS_PK pk = challenger.getPk();

        int k = (int) Math.ceil((double) pk.N.bitLength() / 8);
        BigInteger B = BigInteger.TWO.pow(8*(k-2));
        BigInteger _2B = BigInteger.TWO.multiply(B);
        BigInteger _3B = _2B.add(B);
        Set<Pair<BigInteger, BigInteger>> intervals = new HashSet<>();
        intervals.add(new Pair<BigInteger,BigInteger>(_2B, _3B.subtract(BigInteger.ONE)));
        int i = 1;
        BigInteger s = ceilDivide(pk.N, _3B);

        while (true) {
            if (i == 1 || intervals.size() > 1) {
                // step 2a & 2b
                try {
                    while (!challenger.isPKCSConforming(ciphertext.multiply(s.modPow(pk.exponent, pk.N)).mod(pk.N))) {
                        s = s.add(BigInteger.ONE);
                    }
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            else {
                // step 2c
                Pair<BigInteger, BigInteger> interval = intervals.iterator().next();
                BigInteger r = ceilDivide(interval.second.multiply(s).subtract(_2B), pk.N).multiply(BigInteger.TWO);
                BigInteger rn = r.multiply(pk.N);
                boolean foundS = false;
                while (!foundS) {
                    BigInteger lower = ceilDivide(_2B.add(rn), interval.second);
                    BigInteger upper = _3B.add(rn).divide(interval.first);
                    for (s = lower; s.compareTo(upper) <= 0; s = s.add(BigInteger.ONE)) {
                        try {
                            if (challenger.isPKCSConforming(ciphertext.multiply(s.modPow(pk.exponent, pk.N)).mod(pk.N))) {
                                foundS = true;
                                break;
                            }
                        } catch (Exception e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                    }
                    rn = rn.add(pk.N);
                }
            }

            // step 3
            Set<Pair<BigInteger, BigInteger>> new_intervals = new HashSet<>();
            for (Pair<BigInteger, BigInteger> interval : intervals) {
                BigInteger r = ceilDivide(interval.first.multiply(s).subtract(_3B).add(BigInteger.ONE), pk.N);
                BigInteger stop = interval.second.multiply(s).subtract(_2B).divide(pk.N);
                while (r.compareTo(stop) <= 0) {
                    BigInteger rn = r.multiply(pk.N);
                    BigInteger lower = ceilDivide(_2B.add(rn), s);
                    BigInteger upper = _3B.subtract(BigInteger.ONE).add(rn).divide(s);
                    if (lower.compareTo(upper) <= 0) {
                        new_intervals.add(new Pair<BigInteger,BigInteger>(lower.max(interval.first), upper.min(interval.second)));
                    }
                    r = r.add(BigInteger.ONE);
                }
            }
            if (new_intervals.size() > 1) {
                s = s.add(BigInteger.ONE);
            }
            intervals = new_intervals;

            // step 4
            if (intervals.size() == 1) {
                Pair<BigInteger, BigInteger> interval = intervals.iterator().next();
                if (interval.first.equals(interval.second)) {
                    return new BigInteger(pkcs15Unpad(interval.first));
                }
            }
            i += 1;
        }
    }

    private byte[]  pkcs15Unpad(BigInteger paddedPlainText) {
        byte   repr[] = paddedPlainText.toByteArray();
        // BigInteger removes the most significant 0 byte from the internal representation
        if (repr[0] == 2) {
            for (int i=1; i < repr.length; i++) {
                // EB1 = 00, EB2 = 02, EB3 through EB10 are nonzero. At least one of the bytes EB11 through EBk is 00.
                // EB11 is repr[9] given that BigInteger removes the most significant 0 byte.
                if (repr[i] == 0  &&  i >= 9)  {
                    return  Arrays.copyOfRange(repr, i + 1, repr.length);
                }
            }
        }
        throw  new IllegalArgumentException(paddedPlainText + " is not PKCS padded");
    }
}