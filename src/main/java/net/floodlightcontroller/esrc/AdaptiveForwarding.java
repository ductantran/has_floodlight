package net.floodlightcontroller.esrc;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.internal.OFChannelInfo;
import net.floodlightcontroller.core.internal.OFSwitch;
import net.floodlightcontroller.core.internal.OFSwitchManager;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.StatisticsCollector;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

public class AdaptiveForwarding implements IAdaptiveListener, IOFMessageListener, IFloodlightModule {
    protected IFloodlightProviderService floodlightProvider;
    protected IStatisticsService statisticsService;
    protected AdaptiveRouter adaptiveRouter;
    protected OFSwitchManager switchManager;
    protected StatisticsCollector statisticsCollector;
    protected static Logger logger;

    private int currentPath = 0;

    private List<DatapathId> switchDpids = null;
    private IPv4Address r1MininetIpAddr = IPv4Address.of("10.0.3.1");
    private IPv4Address r2MininetIpAddr = IPv4Address.of("10.0.3.2");
    private IPv4Address clientIpAddr = IPv4Address.of("10.0.1.2");
    private IPv4Address serverIpAddr = IPv4Address.of("10.0.2.2");

    @Override
    public String getName() {
        return AdaptiveForwarding.class.getSimpleName();
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
        l.add(IStatisticsService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        statisticsService = context.getServiceImpl(IStatisticsService.class);
        switchManager = new OFSwitchManager();
        statisticsCollector = new StatisticsCollector();
        adaptiveRouter = new AdaptiveRouter();
        logger = LoggerFactory.getLogger(AdaptiveForwarding.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        adaptiveRouter.addAdaptiveListener(this);
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
            case PACKET_IN:
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
                OFFactory ofFactory = sw.getOFFactory();
                switchDpids = switchManager.getAllSwitchDpids().stream().collect(Collectors.toList());

                if (eth.getEtherType() == EthType.LLDP || eth.getEtherType() == EthType.IPv6) {
                    break;
                }

                if (!statisticsCollector.getBandwidthConsumption().isEmpty()) {
                    DatapathId swId = sw.getId();
                    OFPort p = sw.getPorts().stream().collect(Collectors.toList()).get(0).getPortNo();
                    logger.debug(String.valueOf(statisticsCollector.getBandwidthConsumption(swId, p).getBitsPerSecondRx().getValue()));
                }

                if (sw.getId() == switchDpids.get(0)) {
                    if (eth.getEtherType() == EthType.ARP) {
                        logger.debug("-SWITCH: " + switchDpids.get(0).toString());
                        logger.debug("--ARP");
                        ARP arpPkt = (ARP) eth.getPayload();
                        if (arpPkt.getTargetProtocolAddress().equals(r1MininetIpAddr)) {
                            logger.debug("---To R1");
                            OFPacketOut pktOut = ofFactory.buildPacketOut()
                                    .setData(eth.serialize())
                                    .setActions(Collections.singletonList(ofFactory.actions().output(OFPort.of(1), 0)))
                                    .setInPort(OFPort.CONTROLLER)
                                    .build();
                            sw.write(pktOut);
                        } else if (arpPkt.getTargetProtocolAddress().equals(r2MininetIpAddr)) {
                            logger.debug("---To R2");
                            OFPacketOut pktOut = ofFactory.buildPacketOut()
                                    .setData(eth.serialize())
                                    .setActions(Collections.singletonList(ofFactory.actions().output(OFPort.of(2), 0)))
                                    .setInPort(OFPort.CONTROLLER)
                                    .build();
                            sw.write(pktOut);
                        }
                    } else if (eth.getEtherType() == EthType.IPv4) {
                        IPv4 ipPkt = (IPv4) eth.getPayload();
                        if (ipPkt.getProtocol() == IpProtocol.UDP) break;
                        logger.debug("-SWITCH: " + switchDpids.get(0).toString());
                        logger.debug("--IPv4");
                        Match matchIpToR1 = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, r1MininetIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToR1 = new ArrayList<OFAction>();
                        actionsIpToR1.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(1)).build());
                        OFFlowAdd flowIpToR1 = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToR1)
                                .setActions(actionsIpToR1)
                                .build();
                        sw.write(flowIpToR1);

                        Match matchIpToClient = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, clientIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToClient = new ArrayList<OFAction>();
                        actionsIpToClient.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(1)).build());
                        OFFlowAdd flowIpToClient = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToClient)
                                .setActions(actionsIpToClient)
                                .build();
                        sw.write(flowIpToClient);

                        Match matchIpToR2 = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, r2MininetIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToR2 = new ArrayList<OFAction>();
                        actionsIpToR2.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(2)).build());
                        OFFlowAdd flowIpToR2 = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToR2)
                                .setActions(actionsIpToR2)
                                .build();
                        sw.write(flowIpToR2);

                        Match matchIpToServer = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, serverIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToServer = new ArrayList<OFAction>();
                        actionsIpToServer.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(2)).build());
                        OFFlowAdd flowIpToServer = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToServer)
                                .setActions(actionsIpToServer)
                                .build();
                        sw.write(flowIpToServer);
                    }
                } else if (sw.getId() == switchDpids.get(3)) {
                    if (eth.getEtherType() == EthType.ARP) {
                        logger.debug("-SWITCH: " + sw.getId().toString());
                        logger.debug("--ARP");
                        ARP arpPkt = (ARP) eth.getPayload();
                        if (arpPkt.getTargetProtocolAddress().equals(r1MininetIpAddr)) {
                            logger.debug("---To R1");
                            OFPacketOut pktOut = ofFactory.buildPacketOut()
                                    .setData(eth.serialize())
                                    .setActions(Collections.singletonList(ofFactory.actions().output(OFPort.of(2), 0)))
                                    .setInPort(OFPort.CONTROLLER)
                                    .build();
                            sw.write(pktOut);
                        } else if (arpPkt.getTargetProtocolAddress().equals(r2MininetIpAddr)) {
                            logger.debug("---To R2");
                            OFPacketOut pktOut = ofFactory.buildPacketOut()
                                    .setData(eth.serialize())
                                    .setActions(Collections.singletonList(ofFactory.actions().output(OFPort.of(1), 0)))
                                    .setInPort(OFPort.CONTROLLER)
                                    .build();
                            sw.write(pktOut);
                        }
                    } else if (eth.getEtherType() == EthType.IPv4) {
                        IPv4 ipPkt = (IPv4) eth.getPayload();
                        if (ipPkt.getProtocol() == IpProtocol.UDP) break;
                        logger.debug("-SWITCH: " + sw.getId().toString());
                        logger.debug("--IPv4");
                        Match matchIpToR1 = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, r1MininetIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToR1 = new ArrayList<OFAction>();
                        actionsIpToR1.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(2)).build());
                        OFFlowAdd flowIpToR1 = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToR1)
                                .setActions(actionsIpToR1)
                                .build();
                        sw.write(flowIpToR1);

                        Match matchIpToClient = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, clientIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToClient = new ArrayList<OFAction>();
                        actionsIpToClient.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(2)).build());
                        OFFlowAdd flowIpToClient = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToClient)
                                .setActions(actionsIpToClient)
                                .build();
                        sw.write(flowIpToClient);

                        Match matchIpToR2 = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, r2MininetIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToR2 = new ArrayList<OFAction>();
                        actionsIpToR2.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(1)).build());
                        OFFlowAdd flowIpToR2 = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToR2)
                                .setActions(actionsIpToR2)
                                .build();
                        sw.write(flowIpToR2);

                        Match matchIpToServer = ofFactory.buildMatch()
                                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                                .setExact(MatchField.IPV4_DST, serverIpAddr)
                                .build();
                        ArrayList<OFAction> actionsIpToServer = new ArrayList<OFAction>();
                        actionsIpToServer.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(1)).build());
                        OFFlowAdd flowIpToServer = ofFactory.buildFlowAdd()
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setIdleTimeout(0)
                                .setHardTimeout(0)
                                .setPriority(100)
                                .setMatch(matchIpToServer)
                                .setActions(actionsIpToServer)
                                .build();
                        sw.write(flowIpToServer);
                    }
                } else if (sw.getId() == switchDpids.get(1) || sw.getId() == switchDpids.get(2)) {
                    logger.debug("-SWITCH: " + sw.getId().toString());
                    Match matchArpPort1To2 = ofFactory.buildMatch()
                            .setExact(MatchField.ETH_TYPE, EthType.ARP)
                            .setExact(MatchField.IN_PORT, OFPort.of(1))
                            .build();
                    ArrayList<OFAction> actionsArpPort1To2 = new ArrayList<OFAction>();
                    actionsArpPort1To2.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(2)).build());
                    OFFlowAdd flowArpPort1To2 = ofFactory.buildFlowAdd()
                            .setBufferId(OFBufferId.NO_BUFFER)
                            .setIdleTimeout(0)
                            .setHardTimeout(0)
                            .setPriority(100)
                            .setMatch(matchArpPort1To2)
                            .setActions(actionsArpPort1To2)
                            .build();
                    sw.write(flowArpPort1To2);

                    Match matchArpPort2To1 = ofFactory.buildMatch()
                            .setExact(MatchField.ETH_TYPE, EthType.ARP)
                            .setExact(MatchField.IN_PORT, OFPort.of(2))
                            .build();
                    ArrayList<OFAction> actionsArpPort2To1 = new ArrayList<OFAction>();
                    actionsArpPort2To1.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(1)).build());
                    OFFlowAdd flowArpPort2To1 = ofFactory.buildFlowAdd()
                            .setBufferId(OFBufferId.NO_BUFFER)
                            .setIdleTimeout(0)
                            .setHardTimeout(0)
                            .setPriority(100)
                            .setMatch(matchArpPort2To1)
                            .setActions(actionsArpPort2To1)
                            .build();
                    sw.write(flowArpPort2To1);

                    Match matchIpPort1To2 = ofFactory.buildMatch()
                            .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                            .setExact(MatchField.IN_PORT, OFPort.of(1))
                            .build();
                    ArrayList<OFAction> actionsIpPort1To2 = new ArrayList<OFAction>();
                    actionsIpPort1To2.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(2)).build());
                    OFFlowAdd flowIpPort1To2 = ofFactory.buildFlowAdd()
                            .setBufferId(OFBufferId.NO_BUFFER)
                            .setIdleTimeout(0)
                            .setHardTimeout(0)
                            .setPriority(100)
                            .setMatch(matchIpPort1To2)
                            .setActions(actionsIpPort1To2)
                            .build();
                    sw.write(flowIpPort1To2);

                    Match matchIpPort2To1 = ofFactory.buildMatch()
                            .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                            .setExact(MatchField.IN_PORT, OFPort.of(2))
                            .build();
                    ArrayList<OFAction> actionsIpPort2To1 = new ArrayList<OFAction>();
                    actionsIpPort2To1.add(ofFactory.actions().buildOutput().setMaxLen(0).setPort(OFPort.of(1)).build());
                    OFFlowAdd flowIpPort2To1 = ofFactory.buildFlowAdd()
                            .setBufferId(OFBufferId.NO_BUFFER)
                            .setIdleTimeout(0)
                            .setHardTimeout(0)
                            .setPriority(100)
                            .setMatch(matchIpPort2To1)
                            .setActions(actionsIpPort2To1)
                            .build();
                    sw.write(flowIpPort2To1);
                }

                break;
            default:
                break;
        }
        return Command.CONTINUE;
    }

    @Override
    public void pathChanged() {

    }
}
