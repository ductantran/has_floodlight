package net.floodlightcontroller.esrc;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.internal.IOFSwitchService;
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
    protected IOFSwitchService switchService;
    protected AdaptiveRouter adaptiveRouter;
    protected static Logger logger;

    private Map<DatapathId, Set<Link>> allSwitchLinks;
    private List<DatapathId> switchDpids;
    private Set<Link> linksSet;
    private List<Link> links;
    private Map<IPv4Address, DatapathId> mapHostSwitch;
    private boolean isNetworkDiscovered;

    private List<List<DatapathId>> allPaths;
    private int currentPathIndex = 0;
    private int[] pathThroughputs;

    private static final File file = new File("/home/ubuntu14/file.txt");

    private final IPv4Address h1MininetIpAddr = IPv4Address.of("10.0.3.1");
    private final IPv4Address h2MininetIpAddr = IPv4Address.of("10.0.3.2");
    private final IPv4Address clientIpAddr = IPv4Address.of("10.0.4.2");
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
        switchService = context.getServiceImpl(IOFSwitchService.class);

        adaptiveRouter = new AdaptiveRouter();
        switchDpids = new ArrayList<>();
        linksSet = new HashSet<>();
        links = new ArrayList<>();

        allPaths = new ArrayList<>();
        pathThroughputs = new int[0];

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

        monitorCurrentPath();
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

                allPaths = adaptiveRouter.getAllPathsFromSourceToDestination(mapHostSwitch.get(srcIpAddr), mapHostSwitch.get(dstIpAddr));
                pathThroughputs = new int[allPaths.size()];
                logger.debug("[DFS] [PATHS] " + allPaths.toString());

                adaptiveRouter.findPathfromSource(mapHostSwitch.get(srcIpAddr));
                List<DatapathId> path = adaptiveRouter.getPathToDestination(mapHostSwitch.get(dstIpAddr));

                for (List<DatapathId> aPath : allPaths) {
                    if (path.equals(aPath)) {
                        logger.debug("[DFS+DIJKSTRA] [PATH] " + allPaths.indexOf(aPath) + "/" + (allPaths.size()-1));
                        this.currentPathIndex = allPaths.indexOf(aPath);
                    }
                }

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

        if ((switchDpids.size() == 5) && (links.size() == 12)) {
            isNetworkDiscovered = true;
            HASGraph hasGraph = new HASGraph(switchDpids, links);
            adaptiveRouter.setDijkstraRouter(new HASDijkstra(hasGraph));
            adaptiveRouter.setDFSRouter(new HASDFS(hasGraph));

            logger.debug("[ADAPTIVE] [NETWORK] Topology Discovered");
        } else {
            isNetworkDiscovered = false;
        }
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
//        logger.debug("[FLOW] [ADD] [SW-" + sw.getId().toString() + "] " + flow.toString());
    }

    @Override
    public void pathChanged() {
        switchBetweenPaths();
    }

    private void pathSwitched(List<DatapathId> path) {
        logger.debug("");
        logger.debug("[ADAPTIVE] [SWITCHED] [PATH] " + path.toString());

        for (DatapathId swDpid : path) {
            IOFSwitch sw = switchService.getSwitch(swDpid);

            if (path.indexOf(swDpid) == 0) {
                for (Link link : links) {
                    if (link.getSrc().equals(swDpid)) {
                        if (link.getDst().equals(path.get(path.indexOf(swDpid)+1))) {
                            addFlowWithEthernetMatch(sw, EthType.IPv4, clientIpAddr, serverIpAddr, OFPort.of(1));
                            addFlowWithEthernetMatch(sw, EthType.IPv4, h1MininetIpAddr, h2MininetIpAddr, OFPort.of(1));
                            OFPort forwardingPort = link.getSrcPort();
                            addFlowWithEthernetMatch(sw, EthType.IPv4, serverIpAddr, clientIpAddr, forwardingPort);
                            addFlowWithEthernetMatch(sw, EthType.IPv4, h2MininetIpAddr, h1MininetIpAddr, forwardingPort);
                        }
                    }
                }
            } else if (path.indexOf(swDpid) == path.size()-1) {
                for (Link link : links) {
                    if (link.getSrc().equals(swDpid)) {
                        if (link.getDst().equals(path.get(path.indexOf(swDpid)-1))) {
                            addFlowWithEthernetMatch(sw, EthType.IPv4, serverIpAddr, clientIpAddr, OFPort.of(1));
                            addFlowWithEthernetMatch(sw, EthType.IPv4, h2MininetIpAddr, h1MininetIpAddr, OFPort.of(1));
                            OFPort forwardingPort = link.getSrcPort();
                            addFlowWithEthernetMatch(sw, EthType.IPv4, clientIpAddr, serverIpAddr, forwardingPort);
                            addFlowWithEthernetMatch(sw, EthType.IPv4, h1MininetIpAddr, h2MininetIpAddr, forwardingPort);
                        }
                    }
                }
            } else {
                for (Link link : links) {
                    if (link.getSrc().equals(swDpid)) {
                        if (link.getDst().equals(path.get(path.indexOf(swDpid)+1))) {
                            OFPort forwardingPort = link.getSrcPort();
                            addFlowWithEthernetMatch(sw, EthType.IPv4, serverIpAddr, clientIpAddr, forwardingPort);
                            addFlowWithEthernetMatch(sw, EthType.IPv4, h2MininetIpAddr, h1MininetIpAddr, forwardingPort);
                        } else if (link.getDst().equals(path.get(path.indexOf(swDpid)-1))) {
                            OFPort forwardingPort = link.getSrcPort();
                            addFlowWithEthernetMatch(sw, EthType.IPv4, clientIpAddr, serverIpAddr, forwardingPort);
                            addFlowWithEthernetMatch(sw, EthType.IPv4, h1MininetIpAddr, h2MininetIpAddr, forwardingPort);
                        }
                    }
                }
            }

        }
    }

    private void monitorCurrentPath() {
        int monitoringPeriod = 2000;
        TimerTask monitoringTask = new TimerTask() {
            @Override
            public void run() {
                if (adaptiveRouter.hasStreamingStarted && !adaptiveRouter.getRouteManager().hasRerouted) {
                    logger.debug("");
                    getPathThroughput(allPaths.get(currentPathIndex));

                    String logStr = "[MONITOR] [THROUGHPUTS] ";
                    StringBuilder logStrBuilder = new StringBuilder(logStr);
                    for (int i = 0; i < pathThroughputs.length; i++) {
                        logStrBuilder.append(pathThroughputs[i]);
                        if (i < pathThroughputs.length - 1) logStrBuilder.append(" | ");
                    }
                    logger.debug(logStrBuilder.toString());

                    if (pathThroughputs[currentPathIndex] > 100 && pathThroughputs[currentPathIndex] < 1000) {
                        logger.debug("[MONITOR] Congestion Detected");
                        switchBetweenPaths();
                    }
                }
            }
        };
        Timer timer = new Timer();
        timer.schedule(monitoringTask, 0, monitoringPeriod);
    }

    private void switchBetweenPaths() {
        int t = 2000;
        TimerTask switchingTask = new TimerTask() {
            @Override
            public void run() {
                adaptiveRouter.getRouteManager().hasRerouted = true;
                if (allPaths.size() > 0) {
                    for (List<DatapathId> path : allPaths) {
                        pathSwitched(path);
                        try {
                            Thread.sleep(t);
                            getPathThroughput(path);
                        } catch (InterruptedException e) {
                            logger.debug(e.getMessage());
                        }
                    }

                    int maxThp = 0;
                    int maxThpIndex = 0;
                    String logStr = "[ADAPTIVE] [THROUGHPUTS] ";
                    StringBuilder logStrBuilder = new StringBuilder(logStr);
                    for (int i = 0; i < pathThroughputs.length; i++) {
                        logStrBuilder.append(pathThroughputs[i]);
                        if (i < pathThroughputs.length - 1) logStrBuilder.append(" | ");

                        if (pathThroughputs[i] > maxThp) {
                            maxThp = pathThroughputs[i];
                            maxThpIndex = i;
                        }
                    }
                    logger.debug(logStrBuilder.toString());

                    pathSwitched(allPaths.get(maxThpIndex));
                    currentPathIndex = maxThpIndex;
                    adaptiveRouter.getRouteManager().hasRerouted = false;
                }
            }
        };
        Timer timer = new Timer();
        timer.schedule(switchingTask, 0);
    }

    private void getPathThroughput(List<DatapathId> path) {
        if (!statisticsService.getBandwidthConsumption().isEmpty()) {
            for (List<DatapathId> aPath : allPaths) {
                DatapathId lastSwitchDpid = aPath.get(aPath.size()-1);
                DatapathId measuredSwitchDpid = aPath.get(aPath.size()-2);
                OFPort portToMeasure = null;
                for (Link measuredLink : links) {
                    if (measuredLink.getDst().equals(lastSwitchDpid) && measuredLink.getSrc().equals(measuredSwitchDpid)) {
                        portToMeasure = measuredLink.getSrcPort();
                    }
                }

                if (portToMeasure != null) {
                    SwitchPortBandwidth spBw = statisticsService.getBandwidthConsumption(measuredSwitchDpid, portToMeasure);
                    int rx = (int) spBw.getBitsPerSecondRx().getValue();
                    int tx = (int) spBw.getBitsPerSecondTx().getValue();
                    int throughputInKbps = (rx + tx)/1000;

                    String logStr = "[ADAPTIVE] [THROUGHPUT] [" + spBw.getSwitchId().toString() + "-" + spBw.getSwitchPort().getPortNumber() + "] " + throughputInKbps + "kbps";
                    if (allPaths.indexOf(aPath) == allPaths.indexOf(path)) {
                        logStr += " *";
                        if (throughputInKbps != 0) {
                            pathThroughputs[allPaths.indexOf(path)] = throughputInKbps;
                        }
                    }
                    logger.debug(logStr);
                }
            }
        }
    }
}
