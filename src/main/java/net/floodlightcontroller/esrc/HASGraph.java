package net.floodlightcontroller.esrc;

import net.floodlightcontroller.linkdiscovery.Link;
import org.projectfloodlight.openflow.types.DatapathId;

import java.util.List;

public class HASGraph {
    private final List<DatapathId> switches;
    private final List<Link> links;

    public HASGraph(List<DatapathId> switches, List<Link> links) {
        this.switches = switches;
        this.links = links;
    }

    List<DatapathId> getSwitchDpids() {
        return this.switches;
    }

    List<Link> getLinks() {
        return this.links;
    }
}
