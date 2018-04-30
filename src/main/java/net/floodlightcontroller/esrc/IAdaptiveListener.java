package net.floodlightcontroller.esrc;

public interface IAdaptiveListener {
    default void reroute() {}
    default void pathChanged() {}
}
