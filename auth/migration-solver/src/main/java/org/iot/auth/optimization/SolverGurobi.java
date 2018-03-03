package org.iot.auth.optimization;

import gurobi.*;

import org.iot.auth.optimization.util.SSTVar;
import org.iot.auth.optimization.util.GurobiVar;

import java.util.*;

/**
 *
 * Gurobi implementation of the Solver interface.
 *
 * @author Eunsuk Kang
 */
public class SolverGurobi implements Solver {

    private GRBEnv env;
    private GRBModel model;
    private static String LOG_FILENAME = "mip.log";

    public SolverGurobi(){
        try {
            this.env = new GRBEnv(LOG_FILENAME);
            this.model = new GRBModel(env);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    /**
     * Add a new binary variable with given lower and upper bounds and its weight
     * @return Variable added
     */
    public SSTVar addBinaryVar(String name, double lower, double upper, double weight) {
        GRBVar v = null;
        try {
            v = model.addVar(lower, upper, weight, GRB.BINARY, name);
            //model.update();
        } catch (GRBException e){
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
        return new GurobiVar(v);
    }

    /**
     * Given a set of vars {v_0, v_1, ..., v_n}, build an expression of form
     * v_0 + v_1 + ... + v_n
     * @return Gurobi expression created.
     */
    private GRBLinExpr buildExpr(String name, Map<SSTVar, Double> vars){
        GRBLinExpr expr = new GRBLinExpr();
        vars.forEach((k, v) -> {
            expr.addTerm(v.doubleValue(),((GurobiVar)k).v());
        });
        return expr;
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal v_0 + v_1 + ... + v_n <= upper }
     */
    public void addLTE(String name, Map<SSTVar, Double> vars, double upper){
        GRBLinExpr expr = buildExpr(name, vars);
        try {
            model.addConstr(expr, GRB.LESS_EQUAL, upper, name);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal v_0 + v_1 + ... + v_n >= lower }
     */
    public void addGTE(String name, Map<SSTVar, Double> vars, double lower){
        GRBLinExpr expr = buildExpr(name, vars);
        try {
            model.addConstr(expr, GRB.GREATER_EQUAL, lower, name);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * v_0 + v_1 + ... + v_n = val
     */
    public void addEQ(String name, Map<SSTVar, Double> vars, double val){
        GRBLinExpr expr = buildExpr(name, vars);
        try {
            model.addConstr(expr, GRB.EQUAL, val, name);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal lower <= v_0 + v_1 + ... + v_n <= upper }
     */
    public void addBetween(String name, Map<SSTVar, Double> vars, double lower, double upper){
        GRBLinExpr expr = buildExpr(name, vars);
        try {
            model.addConstr(expr, GRB.GREATER_EQUAL, lower, name + "_a");
            model.addConstr(expr, GRB.LESS_EQUAL, upper, name + "_b");
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    /**
     * Write the model to a file named by out
     */
    public void write(String out){
        try {
            model.write(out);
        } catch (GRBException e){
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    /**
     * Find an optimal solution (maximum or minimum, depending on the param "obj")
     */
    private void optimize(int obj) {
        try {
            model.set(GRB.IntAttr.ModelSense, obj);
            model.optimize();
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    public void minimize(){
        optimize(GRB.MINIMIZE);
    }

    public void maximize(){
        optimize(GRB.MAXIMIZE);
    }

    // methods that should be called only after min/max

    /**
     * @return A set of variables that have the value "val" in the current solution
     */
    public Set<SSTVar> varsWithVal(Set<SSTVar> vars, int val){
        Set<SSTVar> s = new HashSet<SSTVar>();

        try {
            List<GRBVar> vs = Arrays.asList(model.getVars());
            for (SSTVar v : vars) {
                GRBVar var = ((GurobiVar)v).v();
                // GRB.DoubleAttr.X is the Gurobi attribute that represents its value
                if (vs.contains(var) && var.get(GRB.DoubleAttr.X) == val) {
                    s.add(v);
                }
            }
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
        return s;
    }

    /**
     * @return The overall cost of the solution to the current solution.
     */
    public Double cost(){
        double val = 0;
        try {
            val = model.get(GRB.DoubleAttr.ObjVal);
        } catch (GRBException e){
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
        return val;
    }

    /**
     * Reset the environment and its model
     */
    public void dispose(){
        try {
            model.dispose();
            env.dispose();
        } catch (GRBException e){
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }
}
