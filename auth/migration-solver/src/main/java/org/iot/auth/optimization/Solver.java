/*
 * Copyright (c) 2016, Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * IOTAUTH_COPYRIGHT_VERSION_1
 */

package org.iot.auth.optimization;

import org.iot.auth.optimization.util.SSTVar;

import java.util.Map;
import java.util.Set;

/**
 * Generic solver interface
 *
 * @author Eunsuk Kang
 */
public interface Solver {

    /**
     * Add a new binary variable with given lower and upper bounds and its weight
     * @return Variable added
     */
    public SSTVar addBinaryVar(String name, double lower, double upper, double weight);

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal v_0 + v_1 + ... + v_n <= upper }
     */
    public void addLTE(String name, Map<SSTVar, Double> vars, double upper);

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal v_0 + v_1 + ... + v_n  >= lower }
     */
    public void addGTE(String name, Map<SSTVar, Double> vars, double lower);

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * v_0 + v_1 + ... + v_n = val
     */
    public void addEQ(String name, Map<SSTVar, Double> vars, double val);

    /**
     * Given vars = v_0, v_1, ..., v_n, add an expression
     * {@literal lower <= v_0 + v_1 + ... + v_n <= upper }
     */
    public void addBetween(String name, Map<SSTVar, Double> vars, double lower, double upper);

    /**
     * Find a maximum solution to the ILP problem.
     */
    public void minimize();

    /**
     * Find a minimum solution to the ILP problem.
     */
    public void maximize();

    // Methods that should be invoked only after maximize/minimize finds a solution
    /**
     * @return A set of variables that have the value "val" in the current solution
     */
    public Set<SSTVar> varsWithVal(Set<SSTVar> vars, int val);

    /**
     * @return The overall cost of the solution to the current solution.
     */
    public Double cost();

}

