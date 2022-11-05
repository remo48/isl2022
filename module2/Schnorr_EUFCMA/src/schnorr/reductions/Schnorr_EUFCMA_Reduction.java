package schnorr.reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFCMA_Adversary;
import schnorr.SchnorrSignature;
import schnorr.SchnorrSolution;
import schnorr.Schnorr_PK;
import utils.NumberUtils;
import utils.Pair;

public class Schnorr_EUFCMA_Reduction extends A_Schnorr_EUFCMA_Reduction {  
    private Map<Pair<String, IGroupElement>, BigInteger> hashMap;
    private DLog_Challenge<IGroupElement> challenge;

    public Schnorr_EUFCMA_Reduction(I_Schnorr_EUFCMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        return new Schnorr_PK<IGroupElement>(challenge.generator, challenge.x);
    }

    @Override
    public SchnorrSignature<BigInteger> sign(String message) {
        BigInteger p = challenge.generator.getGroupOrder();
        BigInteger e = NumberUtils.getRandomBigInteger(new SecureRandom(), p);
        BigInteger f = NumberUtils.getRandomBigInteger(new SecureRandom(), p);
        IGroupElement r = challenge.x.power(e.negate()).multiply(challenge.generator.power(f));
        hashMap.put(new Pair<String,IGroupElement>(message, r), e);
        return new SchnorrSignature<BigInteger>(e, f);
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {
        Pair<String, IGroupElement> key = new Pair<String, IGroupElement>(message, r);
        BigInteger h = hashMap.computeIfAbsent(key, k -> NumberUtils.getRandomBigInteger(new SecureRandom(), challenge.generator.getGroupOrder()));
        return h;
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        challenge = challenger.getChallenge();
        hashMap = new HashMap<Pair<String, IGroupElement>, BigInteger>();
        Long seed = 42L;
        BigInteger p = challenge.generator.getGroupOrder();
        
        SchnorrSolution<BigInteger> sol;
        adversary.reset(seed);
        sol = adversary.run(this);
        BigInteger s1 = sol.signature.s;
        BigInteger c1 = sol.signature.c;
        
        adversary.reset(seed);
        hashMap.clear();
        sol = adversary.run(this);
        BigInteger s2 = sol.signature.s;
        BigInteger c2 = sol.signature.c;
        BigInteger x = (s1.subtract(s2).mod(p)).multiply(c1.subtract(c2).modInverse(p)).mod(p);
        return x;
    }
}
