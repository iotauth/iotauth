package org.iot.auth.optimization;

import gurobi.*;

import org.iot.auth.util.OjAlgoVar;
import org.iot.auth.util.SSTVar;
import org.iot.auth.util.GurobiVar;
import org.ojalgo.optimisation.Expression;
import org.ojalgo.optimisation.Variable;

import java.util.*;

/**
 * Created by eskang on 5/17/17.
 */
public class SolverGurobi implements Solver {

    private GRBEnv env;
    private GRBModel model;

    public SolverGurobi(){
        try {
            this.env = new GRBEnv("mip1.log");
            this.model = new GRBModel(env);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

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

    private GRBLinExpr setExpr(String name, Map<SSTVar, Double> vars){
        GRBLinExpr expr = new GRBLinExpr();
        vars.forEach((k, v) -> {
            expr.addTerm(v.doubleValue(),((GurobiVar)k).v());
        });
        return expr;
    }

    public void addLTE(String name, Map<SSTVar, Double> vars, double upper){
        GRBLinExpr expr = setExpr(name, vars);
        try {
            model.addConstr(expr, GRB.LESS_EQUAL, upper, name);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    public void addGTE(String name, Map<SSTVar, Double> vars, double lower){
        GRBLinExpr expr = setExpr(name, vars);
        try {
            model.addConstr(expr, GRB.GREATER_EQUAL, lower, name);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    public void addEQ(String name, Map<SSTVar, Double> vars, double val){
        GRBLinExpr expr = setExpr(name, vars);
        try {
            model.addConstr(expr, GRB.EQUAL, val, name);
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    public void addBetween(String name, Map<SSTVar, Double> vars, double lower, double upper){
        GRBLinExpr expr = setExpr(name, vars);
        try {
            model.addConstr(expr, GRB.GREATER_EQUAL, lower, name + "_a");
            model.addConstr(expr, GRB.LESS_EQUAL, upper, name + "_b");
        } catch (GRBException e) {
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

    public void write(String out){
        try {
            model.write(out);
        } catch (GRBException e){
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
    }

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
    public Set<SSTVar> varsWithVal(Set<SSTVar> vars, int val){
        Set<SSTVar> s = new HashSet<SSTVar>();

        try {
            List<GRBVar> vs = Arrays.asList(model.getVars());
            for (SSTVar v : vars) {
                GRBVar var = ((GurobiVar)v).v();
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
