package cdh_quadratic;

import java.math.BigInteger;
import java.util.Random;

import cdh.CDH_Challenge;
import cdh.I_CDH_Challenger;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run} and {@code getChallenge} of this class.
 * Do not change the constructor of this class.
 */
public class CDH_Quad_Reduction extends A_CDH_Quad_Reduction<IGroupElement> {
    CDH_Challenge<IGroupElement> cdh_challenge;

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public CDH_Quad_Reduction() {
        // Do not add any code here!
    }

    @Override
    public IGroupElement run(I_CDH_Challenger<IGroupElement> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DLog challenge.
        CDH_Challenge<IGroupElement> challenge = challenger.getChallenge();

        // your reduction does not need to be tight. I.e., you may call
        // adversary.run(this) multiple times.

        // Remember that this is a group of prime order p.
        // In particular, we have a^(p-1) = 1 mod p for each a != 0.
        IGroupElement g = challenge.generator;
        IGroupElement gX = challenge.x;
        IGroupElement gY = challenge.y;
        BigInteger groupOrderMinusOne = challenge.generator.getGroupOrder().subtract(BigInteger.ONE);

        IGroupElement solution = f1(g, gX, gY);
        IGroupElement solution_d_only = f1(g, gX.power(groupOrderMinusOne), gY.power(groupOrderMinusOne));
        IGroupElement solution_x_zero = f1(g, gX.power(groupOrderMinusOne), gY);
        IGroupElement solution_y_zero = f1(g, gX, gY.power(groupOrderMinusOne));
        IGroupElement axy = solution.multiply(solution_x_zero.invert()).multiply(solution_y_zero.invert()).multiply(solution_d_only);

        BigInteger groupOrder = challenge.generator.getGroupOrder();
        IGroupElement sol1 = f4(challenge.generator, challenge.x.power(groupOrder.subtract(BigInteger.ONE)), challenge.y.power(groupOrder.subtract(BigInteger.ONE)));
        IGroupElement sol2 = f4(challenge.generator, sol1.power(groupOrder.subtract(BigInteger.valueOf(3))), challenge.y);
        IGroupElement sol3 = f4(challenge.generator, challenge.x, sol2);

        // You can use all classes and methods from the util package:
        var randomNumber = NumberUtils.getRandomBigInteger(new Random(), challenge.generator.getGroupOrder());
        var randomString = StringUtils.generateRandomString(new Random(), 10);
        var pair = new Pair<Integer, Integer>(5, 8);
        var triple = new Triple<Integer, Integer, Integer>(13, 21, 34);

        return sol3;
    }

    private IGroupElement f1(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        cdh_challenge = new CDH_Challenge<IGroupElement>(g, gX, gY);
        IGroupElement solution = adversary.run(this);
        return solution;
    }

    private IGroupElement f2(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        IGroupElement solution = f1(g, gX, gY);
        BigInteger groupOrderMinusOne = g.getGroupOrder().subtract(BigInteger.ONE);
        IGroupElement solution_d_only = f1(g, gX.power(groupOrderMinusOne), gY.power(groupOrderMinusOne));
        return solution.multiply(solution_d_only.invert());
    }    
    
    private IGroupElement f3(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        IGroupElement solution = f2(g, gX, gY);
        BigInteger groupOrderMinusOne = g.getGroupOrder().subtract(BigInteger.ONE);
        IGroupElement solution_y_only = f2(g, gX.power(groupOrderMinusOne), gY);
        return solution.multiply(solution_y_only.invert());
    }    
    
    private IGroupElement f4(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        IGroupElement solution = f3(g, gX, gY);
        BigInteger groupOrderMinusOne = g.getGroupOrder().subtract(BigInteger.ONE);
        IGroupElement solution_x_only = f3(g, gX, gY.power(groupOrderMinusOne));
        return solution.multiply(solution_x_only.invert());
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {
        return cdh_challenge;
    }
}
