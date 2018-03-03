package org.iot.auth.optimization.util;

import gurobi.GRB;
import gurobi.GRBException;
import gurobi.GRBVar;

/**
 *
 * Wrapper for Gurobi variable.
 *
 * @author Eunsuk Kang
 */
public class GurobiVar extends SSTVar {
    private final GRBVar v;

    public GurobiVar(GRBVar v){
        this.v = v;
    }

    public GRBVar v(){
        return this.v;
    }

    public String name(){
        String n = null;
        try {
            n = v.get(GRB.StringAttr.VarName);
        } catch (GRBException e){
            System.out.println("Error code: " + e.getErrorCode() + ". " +
                    e.getMessage());
        }
        return n;
    }
}
