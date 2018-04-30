package net.floodlightcontroller.esrc;

import net.floodlightcontroller.linkdiscovery.Link;
import org.projectfloodlight.openflow.types.DatapathId;

import java.util.ArrayList;
import java.util.List;

public class HASDFS {
    public List<DatapathId> nodes;
    public List<Link> edges;

    private List<DatapathId>[] adjacentLists;

    public List<List<DatapathId>> allPaths;

    public HASDFS(HASGraph graph) {
        this.nodes = new ArrayList<>(graph.getSwitchDpids());
        this.edges = new ArrayList<>(graph.getLinks());

        int numOfNodes = this.nodes.size();
        adjacentLists = new ArrayList[numOfNodes];
        for (int i = 0; i < numOfNodes; i++) {
            adjacentLists[i] = new ArrayList<>();
        }



        for (DatapathId node1 : this.nodes) {
            for (DatapathId node2 : this.nodes) {
                for (Link edge : this.edges) {
                    DatapathId srcNode = edge.getSrc();
                    DatapathId dstNode = edge.getDst();
                    if (srcNode.equals(node1) && dstNode.equals(node2)) {
                        adjacentLists[this.nodes.indexOf(srcNode)].add(dstNode);
                    }
                }
            }
        }


        allPaths = new ArrayList<>();
    }

    public void searchAllPathsFromSourceToDestination(DatapathId srcDpid, DatapathId dstDpid) {
        allPaths = new ArrayList<>();

        int numOfNodes = this.nodes.size();
        boolean[] isVisited = new boolean[numOfNodes];

        List<DatapathId> path = new ArrayList<>();
        path.add(srcDpid);

        execute(srcDpid, dstDpid, isVisited, path);
    }

    private void execute(DatapathId src, DatapathId dst, boolean[] isVisited, List<DatapathId> path) {
        isVisited[this.nodes.indexOf(src)] = true;

        if (src.equals(dst)) {
//            System.out.println(path);
            this.allPaths.add(new ArrayList<>(path));
        }

        for (DatapathId node : adjacentLists[this.nodes.indexOf(src)]) {
            if (!isVisited[this.nodes.indexOf(node)]) {
                path.add(node);
                execute(node, dst, isVisited, path);
                path.remove(node);
            }
        }

        isVisited[this.nodes.indexOf(src)] = false;
    }
}
