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
    private DataInputStream input = null;

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

//                        input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                        input = new DataInputStream(socket.getInputStream());
                        InputStreamReader ir = new InputStreamReader(socket.getInputStream());
                        BufferedReader br = new BufferedReader(ir);

                        while (br.readLine() != null) {
                            try {
                                String line = br.readLine();
                                System.out.println(line);
                                notifyListenersOnRerouting();
                            } catch (IOException e) {
                                System.out.println("Error reading: " + e.getMessage());
                                break;
                            }
                        }
                        System.out.println("Closing connection...");
                        socket.close();
                        input.close();
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
}
