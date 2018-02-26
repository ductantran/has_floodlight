package net.floodlightcontroller.esrc;

import net.floodlightcontroller.packet.Data;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;

import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class AdaptiveRouter implements IAdaptiveService {
    private List<IAdaptiveListener> adaptiveListeners = new ArrayList<IAdaptiveListener>();

    private HASDijkstra hasDijkstra;

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

    public AdaptiveRouter() {

    }

    public HASDijkstra getDijkstraRouter() {
        return hasDijkstra;
    }

    public void setDijkstraRouter(HASDijkstra hasDijkstra) {
        this.hasDijkstra = hasDijkstra;
    }

    public List<DatapathId> route(DatapathId srcSwitch, DatapathId dstSwitch) {
        hasDijkstra.execute(srcSwitch);
        return hasDijkstra.getPath(dstSwitch);
    }

//    private void route() {
//        TimerTask timerTask = new TimerTask() {
//            @Override
//            public void run() {
//                notifyListenersOnPathChange();
//            }
//        };
//        Timer timer = new Timer();
//        timer.scheduleAtFixedRate(timerTask, 0,5000);
//    }

    private void notifyListenersOnPathChange() {
        for (IAdaptiveListener listener : adaptiveListeners) {
            listener.pathChanged();
        }
    }
}
