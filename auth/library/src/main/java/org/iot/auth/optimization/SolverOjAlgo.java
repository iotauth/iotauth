package org.iot.auth.optimization;

import org.iot.auth.util.OjAlgoVar;
import org.ojalgo.netio.BasicLogger;
import org.ojalgo.optimisation.Expression;
import org.ojalgo.optimisation.ExpressionsBasedModel;
import org.ojalgo.optimisation.Optimisation;
import org.ojalgo.optimisation.Variable;
import org.iot.auth.util.SSTVar;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;

/**
 *
 * Solver that uses the OjAlgo package as the underlying ILP engine.
 *
 * @author Eunsuk Kang
 */
public class SolverOjAlgo implements Solver {

    private final ExpressionsBasedModel model = new ExpressionsBasedModel();
    private Optimisation.Result result = null;

    public SSTVar addBinaryVar(String name, double lower, double upper, double weight){
        Variable v = Variable.make(name).lower(lower).upper(upper).weight(weight);
        v.integer(true);
        model.addVariable(v);
        return new OjAlgoVar(v);
    }

    private Expression setExpr(String name, Map<SSTVar, Double> vars){
        Expression expr = model.addExpression(name);
        vars.forEach((k, v) -> {
            expr.set(((OjAlgoVar)k).v(), v.doubleValue());
        });
        return expr;
    }

    public void addLTE(String name, Map<SSTVar, Double> vars, double upper){
        setExpr(name, vars).upper(upper);
    }

    public void addGTE(String name, Map<SSTVar, Double> vars, double lower){
        setExpr(name, vars).lower(lower);
    }

    public void addEQ(String name, Map<SSTVar, Double> vars, double val){
        setExpr(name, vars).lower(val).upper(val);
    }

    public void addBetween(String name, Map<SSTVar, Double> vars, double lower, double upper){
        setExpr(name, vars).lower(lower).upper(upper);
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

    public Double cost(){
        if (result == null) return null;
        return result.getValue();
    }
}
