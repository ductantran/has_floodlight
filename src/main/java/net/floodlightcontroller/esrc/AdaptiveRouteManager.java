package net.floodlightcontroller.esrc;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class AdaptiveRouteManager implements IAdaptiveService {
    private List<IAdaptiveListener> adaptiveListeners = new ArrayList<IAdaptiveListener>();

    private Socket socket = null;
    private ServerSocket serverSocket = null;
    public Boolean hasRerouted = false;

    public AdaptiveRouteManager(int port) {
        TimerTask timerTask = new TimerTask() {
            @Override
            public void run() {
                try {
                    serverSocket = new ServerSocket(port);
                    System.out.println("Server socket created. Waiting for client...");

                    while (true) {
                        socket = serverSocket.accept();
                        System.out.println("Client connected...");

                        BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        String line;

                        while ((line = br.readLine()) != null) {
                            if (line.equals("Start")) {
                                notifyListenersOnStarting();
                            }
                            if (line.equals("Stop")) {
                                notifyListenersOnStopping();
                            }
                            if (line.equals("Reroute") && !hasRerouted) {
                                notifyListenersOnRerouting();
                            }
                        }
                        br.close();
                        System.out.println("Closing connection...");
                        socket.close();
                    }
                } catch (IOException e) {
                    System.out.println("Cannot create socket!");
                    System.out.println(e.getMessage());
                }
            }
        };
        Timer timer = new Timer();
        timer.schedule(timerTask, 0);
    }

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

    private void notifyListenersOnRerouting() {
        for (IAdaptiveListener listener : adaptiveListeners) {
            listener.reroute();
        }
    }

    private void notifyListenersOnStarting() {
        for (IAdaptiveListener listener : adaptiveListeners) {
            listener.start();
        }
    }

    private void notifyListenersOnStopping() {
        for (IAdaptiveListener listener : adaptiveListeners) {
            listener.stop();
        }
    }
}
