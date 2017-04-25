package org.iot.auth.optimization;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.iot.auth.util.SSTGraph;
import org.ojalgo.OjAlgoUtils;
import org.ojalgo.netio.BasicLogger;
import org.ojalgo.optimisation.Expression;
import org.ojalgo.optimisation.ExpressionsBasedModel;
import org.ojalgo.optimisation.Optimisation;
import org.ojalgo.optimisation.Variable;

/**
 *
 * A plan for migrating things to Auths
 *
 * @author Eunsuk Kang
 */
public class MigrationPlan {
    private final Map<String,String> move;
    private final double totalCost;

    public MigrationPlan(SSTGraph network, ExpressionsBasedModel model, Optimisation.Result result){
        move = new HashMap<String,String>();
        for (Variable v : model.getFreeVariables()){
            if (v.getName().startsWith(SSTGraph.CONNECTED) &&
                    result.get(model.indexOf(v)).intValue() == 1){
                String[] tokens = v.getName().split(Solver.DELIM);
                String auth = tokens[1];
                String thing = tokens[2];
                move.put(thing, auth);
            }
        }
        totalCost = result.getValue();
    }

    public Set<String> thingsToMove() {
        return move.keySet();
    }

    public String moveTo(String thing) {
        return move.get(thing);
    }

    @Override
    public String toString(){
        String s = "";
        s += "The total communication cost of the migrated network is " + totalCost + "\n";
        for (String thing : move.keySet()){
            String auth = move.get(thing);
            s += "Migrate " + thing + " to " + auth + "\n";
        }
        return s;
    }
}
