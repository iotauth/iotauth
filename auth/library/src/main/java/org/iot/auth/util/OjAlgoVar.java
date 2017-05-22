package org.iot.auth.util;

import org.ojalgo.optimisation.Variable;

/**
 * Created by eskang on 5/17/17.
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
