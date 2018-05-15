package net.floodlightcontroller.esrc;

public interface IAdaptiveListener {
    default void start() {}
    default void stop() {}
    default void reroute() {}
    default void pathChanged() {}
}
