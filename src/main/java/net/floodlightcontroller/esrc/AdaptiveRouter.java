package net.floodlightcontroller.esrc;

import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.packet.Data;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;

import java.util.*;

public class AdaptiveRouter implements IAdaptiveService, IAdaptiveListener {
    private List<IAdaptiveListener> adaptiveListeners = new ArrayList<IAdaptiveListener>();

    private HASDijkstra hasDijkstra;
    private HASDFS hasDFS;
    private AdaptiveRouteManager routeManager;

    private DatapathId srcSw = null;
    private DatapathId dstSw = null;

    @Override
    public void addAdaptiveListener(IAdaptiveListener listener) {
        adaptiveListeners.add(listener);
    }

    @Override
    public void removeAdaptiveListener(IAdaptiveListener listener) {
        if (adaptiveListeners.contains(listener)) {
            adaptiveListeners.remove(listener);
        }
    }

    @Override
    public void reroute() {
        System.out.println("REROUTE");
//        updateLinkCost();
        findPathfromSource(srcSw);
        notifyListenersOnPathChange();
    }

    public AdaptiveRouter() {
//        routeManager = new AdaptiveRouteManager(8888);
//        routeManager.addAdaptiveListener(this);

    }

    public HASDijkstra getDijkstraRouter() {
        return hasDijkstra;
    }

    public void setDijkstraRouter(HASDijkstra hasDijkstra) {
        this.hasDijkstra = hasDijkstra;
    }

    public void setDFSRouter(HASDFS hasDFS) {
        this.hasDFS = hasDFS;
    }

    public List<List<DatapathId>> getAllPathsFromSourceToDestination(DatapathId srcSwitch, DatapathId dstSwitch) {
        hasDFS.searchAllPathsFromSourceToDestination(srcSwitch, dstSwitch);
        return hasDFS.allPaths;
    }

    public void findPathfromSource(DatapathId srcSwitch) {
        this.srcSw = srcSwitch;
        hasDijkstra.execute(srcSw);
    }

    public List<DatapathId> getPathToDestination(DatapathId dstSwitch) {
        this.dstSw = dstSwitch;
        return hasDijkstra.getPath(dstSw);
    }

    public List<DatapathId> getPath() {
        return hasDijkstra.getPath(dstSw);
    }

    private void notifyListenersOnPathChange() {
        for (IAdaptiveListener listener : adaptiveListeners) {
            listener.pathChanged();
        }
    }

    public void updateLinkCost() {
        List<Link> links = hasDijkstra.edges;
        Random rand = new Random();
        for (Link link1 : links) {
            for (Link link2 : links) {
                if (link1.getSrc().equals(link2.getDst()) && link1.getDst().equals(link2.getSrc())) {
                    int weight = rand.nextInt(100) + 1;
                    link1.setWeight(weight);
                    link2.setWeight(weight);
                    System.out.println("[LINK-UPDATED] " + link1.toString());
                }
            }
        }
    }
}
