package katzwang.reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import ddh.DDH_Challenge;
import ddh.I_DDH_Challenger;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFCMA_Adversary;
import katzwang.KatzWangPK;
import katzwang.KatzWangSignature;
import katzwang.KatzWangSolution;
import utils.NumberUtils;
import utils.Triple;

public class KatzWang_EUFCMA_Reduction extends A_KatzWang_EUFCMA_Reduction {
    private Map<Triple<IGroupElement, IGroupElement, String>, BigInteger> hashMap;
    DDH_Challenge<IGroupElement> challenge;

    public KatzWang_EUFCMA_Reduction(A_KatzWang_EUFCMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {
        challenge = challenger.getChallenge();
        hashMap = new HashMap<>();

        KatzWangSolution<BigInteger> solution = adversary.run(this);
        if (solution == null) {
            return false;
        }

        KatzWangSignature<BigInteger> signature = solution.signature;
        IGroupElement a = challenge.generator.power(signature.s).multiply(challenge.y.power(signature.c.negate()));
        IGroupElement b = challenge.x.power(signature.s).multiply(challenge.z.power(signature.c.negate()));
        BigInteger c = hash(a, b, solution.message);

        return c.equals(signature.c);
    }

    @Override
    public KatzWangPK<IGroupElement> getChallenge() {
        return new KatzWangPK<IGroupElement>(challenge.generator, challenge.x, challenge.y, challenge.z);
    }

    @Override
    public BigInteger hash(IGroupElement comm1, IGroupElement comm2, String message) {
        Triple<IGroupElement, IGroupElement, String> key = new Triple<IGroupElement,IGroupElement,String>(comm1, comm2, message);
        BigInteger h = hashMap.computeIfAbsent(key, k -> NumberUtils.getRandomBigInteger(new SecureRandom(), challenge.generator.getGroupOrder()));
        return h;
    }

    @Override
    public KatzWangSignature<BigInteger> sign(String message) {
        BigInteger c = NumberUtils.getRandomBigInteger(new SecureRandom(), challenge.generator.getGroupOrder());
        BigInteger s = NumberUtils.getRandomBigInteger(new SecureRandom(), challenge.generator.getGroupOrder());
        IGroupElement a = challenge.generator.power(s).multiply(challenge.y.power(c.negate()));
        IGroupElement b = challenge.x.power(s).multiply(challenge.z.power(c.negate()));
        Triple<IGroupElement, IGroupElement, String> key = new Triple<IGroupElement,IGroupElement,String>(a, b, message);
        hashMap.put(key, c);
        return new KatzWangSignature<BigInteger>(c, s);
    }
}
