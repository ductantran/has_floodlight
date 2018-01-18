package net.floodlightcontroller.esrc;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IAdaptiveService extends IFloodlightService {
    public void addAdaptiveListener(IAdaptiveListener listener);
    public void removeAdaptiveListener(IAdaptiveListener listener);
}
