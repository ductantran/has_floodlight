package net.floodlightcontroller.esrc;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.StatisticsCollector;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class AdaptiveForwarder implements IAdaptiveListener, IOFMessageListener, ILinkDiscoveryListener, IFloodlightModule {
    protected IFloodlightProviderService floodlightProvider;
    protected IStatisticsService statisticsService;
    protected ILinkDiscoveryService linkService;
    protected AdaptiveRouter adaptiveRouter;
    protected static Logger logger;

    private Map<DatapathId, Set<Link>> allSwitchLinks;
    private List<DatapathId> switchDpids;
    private Set<Link> linksSet;
    private List<Link> links;
    private Map<IPv4Address, DatapathId> mapHostSwitch;
    private boolean isNetworkDiscovered;

    private static final File file = new File("/home/ubuntu14/file.txt");

    private final IPv4Address h1MininetIpAddr = IPv4Address.of("10.0.3.1");
    private final IPv4Address h2MininetIpAddr = IPv4Address.of("10.0.3.2");
    private final IPv4Address clientIpAddr = IPv4Address.of("10.0.1.2");
    private final IPv4Address serverIpAddr = IPv4Address.of("10.0.2.2");

    @Override
    public String getName() {
        return AdaptiveForwarder.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(ILinkDiscoveryService.class);
        l.add(IStatisticsService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        logger = LoggerFactory.getLogger(AdaptiveForwarder.class);
        isNetworkDiscovered = false;

        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        statisticsService = context.getServiceImpl(IStatisticsService.class);
        linkService = context.getServiceImpl(ILinkDiscoveryService.class);

        adaptiveRouter = new AdaptiveRouter();
        switchDpids = new ArrayList<>();
        linksSet = new HashSet<>();
        links = new ArrayList<>();

        mapHostSwitch = new HashMap<>();
        mapHostSwitch.put(h1MininetIpAddr, DatapathId.of("00:00:00:00:00:00:00:01"));
        mapHostSwitch.put(clientIpAddr, DatapathId.of("00:00:00:00:00:00:00:01"));
        mapHostSwitch.put(h2MininetIpAddr, DatapathId.of("00:00:00:00:00:00:00:02"));
        mapHostSwitch.put(serverIpAddr, DatapathId.of("00:00:00:00:00:00:00:02"));
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        linkService.addListener(this);
        adaptiveRouter.addAdaptiveListener(this);

        FileWriter fr = null;
        try {
            fr = new FileWriter(file, false);
            fr.write("");
        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                fr.close();
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        getLinkBandwidth();
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (!isNetworkDiscovered) {
            return Command.CONTINUE;
        }

        switch (msg.getType()) {
            case PACKET_IN:
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

                if (eth.isMulticast() || eth.getEtherType() == EthType.LLDP || eth.getEtherType() == EthType.IPv6) {
                    break;
                }

                IPv4Address srcIpAddr = null;
                IPv4Address dstIpAddr = null;

                if (eth.getEtherType() == EthType.ARP) {
                    ARP arpPkt = (ARP) eth.getPayload();
                    srcIpAddr = arpPkt.getSenderProtocolAddress();
                    dstIpAddr = arpPkt.getTargetProtocolAddress();
                    logger.debug("[PKT-IN] [SW-" + sw.getId().toString() + "] [ARP] "
                            + srcIpAddr.toString() + " -> " + dstIpAddr.toString());
                } else if (eth.getEtherType() == EthType.IPv4) {
                    IPv4 ipPkt = (IPv4) eth.getPayload();
                    if (ipPkt.getProtocol().equals(IpProtocol.UDP)) break;
                    srcIpAddr = ipPkt.getSourceAddress();
                    dstIpAddr = ipPkt.getDestinationAddress();
                    logger.debug("[PKT-IN] [SW-" + sw.getId().toString() + "] [IPv4] "
                            + srcIpAddr.toString() + " -> " + dstIpAddr.toString());
                } else {
                    return Command.CONTINUE;
                }

                List<DatapathId> path = adaptiveRouter.route(mapHostSwitch.get(srcIpAddr), mapHostSwitch.get(dstIpAddr));

                logger.debug("[DIJKSTRA] [PATH] " + path.toString());

                for (DatapathId swDpid : path) {
                    if (sw.getId().equals(swDpid)) {
                        if (path.indexOf(swDpid) == path.size()-1) {
                            addFlowWithEthernetMatch(sw, eth.getEtherType(), srcIpAddr, dstIpAddr, OFPort.of(1));
                        } else {
                            for (Link link : links) {
                                if (link.getSrc().equals(swDpid)) {
                                    if (link.getDst().equals(path.get(path.indexOf(swDpid)+1))) {
                                        OFPort forwardingPort = link.getSrcPort();
                                        addFlowWithEthernetMatch(sw, eth.getEtherType(), srcIpAddr, dstIpAddr, forwardingPort);
                                    }
                                }
                            }
                        }
                    }
                }

                break;
            default:
                break;
        }
        return Command.CONTINUE;
    }

    @Override
    public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
        allSwitchLinks = linkService.getSwitchLinks();
        switchDpids = new ArrayList<>(allSwitchLinks.keySet());

        for (Set<Link> linkSet : allSwitchLinks.values()) {
            linksSet.addAll(linkSet);
        }
        links = new ArrayList<>(linksSet);

        logger.debug("NUMBER OF SWITCHES: " + switchDpids.size());
        logger.debug("NUMBER OF LINKS: " + links.size());

        if ((switchDpids.size() == 6) && (links.size() == 14)) {
            isNetworkDiscovered = true;
            adaptiveRouter.setDijkstraRouter(new HASDijkstra(new HASGraph(switchDpids, links)));
        } else {
            isNetworkDiscovered = false;
        }
    }

    private void addFlowWithEthernetMatch(IOFSwitch sw, EthType ethType, OFPort inPort, OFPort outPort) {
        OFFactory ofFactory = sw.getOFFactory();
        Match match = ofFactory.buildMatch()
                .setExact(MatchField.ETH_TYPE, ethType)
                .setExact(MatchField.IN_PORT, inPort)
                .build();
        ArrayList<OFAction> actions = new ArrayList<OFAction>();
        actions.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(outPort).build());
        OFFlowAdd flow = ofFactory.buildFlowAdd()
                .setBufferId(OFBufferId.NO_BUFFER)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .setPriority(100)
                .setMatch(match)
                .setActions(actions)
                .build();
        sw.write(flow);
    }

    private void addFlowWithEthernetMatch(IOFSwitch sw, EthType ethType, IPv4Address srcIpAddr, IPv4Address dstIpAddr, OFPort outPort) {
        OFFactory ofFactory = sw.getOFFactory();
        Match match;
        match = ofFactory.buildMatch()
                .setExact(MatchField.ETH_TYPE, ethType)
                .setExact(MatchField.IPV4_SRC, srcIpAddr)
                .setExact(MatchField.IPV4_DST, dstIpAddr)
                .build();
        ArrayList<OFAction> actions = new ArrayList<OFAction>();
        actions.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(outPort).build());
        OFFlowAdd flow = ofFactory.buildFlowAdd()
                .setBufferId(OFBufferId.NO_BUFFER)
                .setIdleTimeout(0)
                .setHardTimeout(0)
                .setMatch(match)
                .setActions(actions)
                .build();
        sw.write(flow);
        logger.debug("[FLOW] [ADD] [SW-" + sw.getId().toString() + "] " + flow.toString());
    }

    @Override
    public void pathChanged() {
    }

    private void getLinkBandwidth() {
        TimerTask timerTask = new TimerTask() {
            @Override
            public void run() {
                if (isNetworkDiscovered) {
                    if (!statisticsService.getBandwidthConsumption().isEmpty()) {
                        SwitchPortBandwidth b = statisticsService.getBandwidthConsumption(switchDpids.get(2), OFPort.of(1));
                        int rx = (int) b.getBitsPerSecondRx().getValue();
                        int tx = (int) b.getBitsPerSecondTx().getValue();
                        logger.debug("[ADAPTIVE] [BANDWIDTH] [" + b.getSwitchId().toString() + "-" + b.getSwitchPort().getPortNumber() + "]");
                        logger.debug("---------- RX: " + rx/1000 + "kbps");
                        logger.debug("---------- TX: " + tx/1000 + "kbps");
                        FileWriter fr = null;
                        try {
                            fr = new FileWriter(file, true);
                            fr.write((rx+tx)/1000 + "\n");
                        } catch (IOException e) {
                            logger.debug(e.getMessage());
                        } finally {
                            try {
                                fr.close();
                            } catch (IOException e) {
                                logger.debug(e.getMessage());
                            }
                        }
                    }
                }
            }
        };
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(timerTask, 0,1000);
    }
}
