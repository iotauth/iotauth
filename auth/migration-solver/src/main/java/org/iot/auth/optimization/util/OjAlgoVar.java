package org.iot.auth.optimization.util;

import org.ojalgo.optimisation.Variable;

/**
 *
 * Wrapper for OjAlgo variables
 *
 * @author Eunsuk Kang
 */
public class OjAlgoVar extends SSTVar {

    private final Variable v;

    public OjAlgoVar(Variable v){
        this.v = v;
    }

    public Variable v(){
        return this.v;
    }

    public String name(){
        return this.v.getName();
    }
}
