package net.floodlightcontroller.esrc;

import net.floodlightcontroller.linkdiscovery.Link;
import org.projectfloodlight.openflow.types.DatapathId;

import java.util.*;

public class HASDijkstra {
    public List<DatapathId> nodes;
    public List<Link> edges;
    private Set<DatapathId> settledNodes;
    private Set<DatapathId> unSettledNodes;
    private Map<DatapathId, DatapathId> predecessors;
    private Map<DatapathId, Integer> distance;

    public HASDijkstra(HASGraph graph) {
        this.nodes = new ArrayList<>(graph.getSwitchDpids());
        this.edges = new ArrayList<>(graph.getLinks());
    }

    public void execute(DatapathId source) {
        settledNodes = new HashSet<>();
        unSettledNodes = new HashSet<>();
        distance = new HashMap<>();
        predecessors = new HashMap<>();
        distance.put(source, 0);
        unSettledNodes.add(source);
        while (unSettledNodes.size() > 0) {
            DatapathId nodeId = getMinimum(unSettledNodes);
            settledNodes.add(nodeId);
            unSettledNodes.remove(nodeId);
            findMinimalDistances(nodeId);
        }
    }

    private void findMinimalDistances(DatapathId nodeId) {
        List<DatapathId> adjacentNodes = getNeighbors(nodeId);
        for (DatapathId targetId : adjacentNodes) {
            if (getShortestDistance(targetId) > getShortestDistance(nodeId)
                    + getDistance(nodeId, targetId)) {
                distance.put(targetId, getShortestDistance(nodeId)
                        + getDistance(nodeId, targetId));
                predecessors.put(targetId, nodeId);
                unSettledNodes.add(targetId);
            }
        }

    }

    private int getDistance(DatapathId nodeId, DatapathId targetId) {
        for (Link edge : edges) {
            if (edge.getSrc().equals(nodeId)
                    && edge.getDst().equals(targetId)) {
                return edge.getWeight();
            }
        }
        throw new RuntimeException("Should not happen");
    }

    private List<DatapathId> getNeighbors(DatapathId nodeId) {
        List<DatapathId> neighbors = new ArrayList<>();
        for (Link edge : edges) {
            if (edge.getSrc().equals(nodeId)
                    && !isSettled(edge.getDst())) {
                neighbors.add(edge.getDst());
            }
        }
        return neighbors;
    }

    private DatapathId getMinimum(Set<DatapathId> nodeIds) {
        DatapathId minimum = null;
        for (DatapathId nodeId : nodeIds) {
            if (minimum == null) {
                minimum = nodeId;
            } else {
                if (getShortestDistance(nodeId) < getShortestDistance(minimum)) {
                    minimum = nodeId;
                }
            }
        }
        return minimum;
    }

    private boolean isSettled(DatapathId nodeId) {
        return settledNodes.contains(nodeId);
    }

    private int getShortestDistance(DatapathId destination) {
        Integer d = distance.get(destination);
        if (d == null) {
            return Integer.MAX_VALUE;
        } else {
            return d;
        }
    }

    /*
     * This method returns the path from the source to the selected target and
     * NULL if no path exists
     */
    public LinkedList<DatapathId> getPath(DatapathId targetId) {
        LinkedList<DatapathId> path = new LinkedList<>();
        DatapathId stepId = targetId;
        // check if a path exists
        if (predecessors.get(stepId) == null) {
            return null;
        }
        path.add(stepId);
        while (predecessors.get(stepId) != null) {
            stepId = predecessors.get(stepId);
            path.add(stepId);
        }
        // Put it into the correct order
        Collections.reverse(path);
        return path;
    }
}
