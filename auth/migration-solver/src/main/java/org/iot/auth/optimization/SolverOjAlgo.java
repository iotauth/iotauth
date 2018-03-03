package org.iot.auth.optimization;

import org.iot.auth.optimization.util.OjAlgoVar;
import org.ojalgo.netio.BasicLogger;
import org.ojalgo.optimisation.Expression;
import org.ojalgo.optimisation.ExpressionsBasedModel;
import org.ojalgo.optimisation.Optimisation;
import org.ojalgo.optimisation.Variable;
import org.iot.auth.optimization.util.SSTVar;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;

/**
 *
 * OjAlgo implementation of the Solver interface.
 *
 * @author Eunsuk Kang
 */
public class SolverOjAlgo implements Solver {

    private final ExpressionsBasedModel model = new ExpressionsBasedModel();
    private Optimisation.Result result = null;

    /**
     * Add a new binary variable with given lower and upper bounds and its weight
     * @return Variable added
     */
    public SSTVar addBinaryVar(String name, double lower, double upper, double weight){
        Variable v = Variable.make(name).lower(lower).upper(upper).weight(weight);
        v.integer(true);
        model.addVariable(v);
        return new OjAlgoVar(v);
    }

    /**
     * Given a set of vars {v_0, v_1, ..., v_n}, build an expression of form
     * v_0 + v_1 + ... + v_n
     * @return OjAlgo expression created.
     */
    private Expression buildExpr(String name, Map<SSTVar, Double> vars){
        Expression expr = model.addExpression(name);
        vars.forEach((k, v) -> {
            expr.set(((OjAlgoVar)k).v(), v.doubleValue());
        });
        return expr;
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal v_0 + v_1 + ... + v_n <= upper }
     */
    public void addLTE(String name, Map<SSTVar, Double> vars, double upper){
        buildExpr(name, vars).upper(upper);
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal v_0 + v_1 + ... + v_n >= lower }
     */
    public void addGTE(String name, Map<SSTVar, Double> vars, double lower){
        buildExpr(name, vars).lower(lower);
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * v_0 + v_1 + ... + v_n = eq
     */
    public void addEQ(String name, Map<SSTVar, Double> vars, double val){
        buildExpr(name, vars).lower(val).upper(val);
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal lower <= v_0 + v_1 + ... + v_n <= upper }
     */
    public void addBetween(String name, Map<SSTVar, Double> vars, double lower, double upper){
        buildExpr(name, vars).lower(lower).upper(upper);
    }

    public void minimize(){
        this.result = model.minimise();
        // Print the result, and the model
        BasicLogger.debug();
        BasicLogger.debug(result);
        BasicLogger.debug();
        BasicLogger.debug(model);
        BasicLogger.debug();
    }

    public void maximize(){
        this.result = model.minimise();
        // Print the result, and the model
        BasicLogger.debug();
        BasicLogger.debug(result);
        BasicLogger.debug();
        BasicLogger.debug(model);
        BasicLogger.debug();
    }

    /**
     * @return A set of variables that have the value "val" in the current solution
     */
    public Set<SSTVar> varsWithVal(Set<SSTVar> vars, int val){
        Set<SSTVar> s = new HashSet<SSTVar>();
        if (result == null) return null;
        List<Variable> freevars = model.getFreeVariables();
        vars.forEach((v) ->{
            Variable var = ((OjAlgoVar)v).v();
            if (freevars.contains(var) &&
                    result.get(model.indexOf(var)).intValue() == val)
                s.add(v);
        });
        return s;
    }

    /**
     * @return The overall cost of the solution to the current solution.
     */
    public Double cost(){
        if (result == null) return null;
        return result.getValue();
    }

}
