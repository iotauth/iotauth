package org.iot.auth.util;

/**
 *
 * Generic representation of directed, weighted graphs.
 *
 * Mutable.
 *
 * @author Eunsuk Kang
 *
 */
abstract public class Graph<X> {

    protected final java.util.Set<Edge> edges = new java.util.HashSet<Edge>();

    public class Edge {
        public final X from;
        public final X to;
        protected Edge(X from, X to){
            this.from = from;
            this.to = to;
        }
    }

    public void addEdge(X from, X to){
        edges.add(new Edge(from,to));
    }
}

