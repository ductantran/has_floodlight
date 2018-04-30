package net.floodlightcontroller.esrc;

import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class AdaptiveRouter implements IAdaptiveService {
    private List<IAdaptiveListener> adaptiveListeners = new ArrayList<IAdaptiveListener>();

    private int path = 0;

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
        route();
    }

    public int getPath() {
        return path;
    }

    private void route() {
        TimerTask timerTask = new TimerTask() {
            @Override
            public void run() {
//                path += 1;
                notifyListenersOnPathChange();
            }
        };
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(timerTask, 0,3000);
    }

    private void notifyListenersOnPathChange() {
        for (IAdaptiveListener listener : adaptiveListeners) {
            listener.pathChanged();
        }
    }
}
