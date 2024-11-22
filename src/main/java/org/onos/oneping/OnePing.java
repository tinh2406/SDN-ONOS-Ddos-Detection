/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onos.oneping;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onos.httpddosdetector.classifier.Classifier;
import org.onos.httpddosdetector.classifier.randomforest.RandomForestBinClassifier;
import org.onos.httpddosdetector.flow.parser.FlowData;
import org.onos.httpddosdetector.keys.AttackKey;
import org.onos.httpddosdetector.keys.DistributedAttackKey;
import org.onos.httpddosdetector.keys.FlowKey;
import org.onos.api.flow.FlowApi;
import org.onos.api.flow.FlowRuleId;
import org.onos.api.ApiResponse;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Sample application that permits only one ICMP ping per minute for a unique
 * src/dst MAC pair per switch.
 */
@Component(immediate = true)
public class OnePing {

    private static final Logger log = LoggerFactory.getLogger(OnePing.class);

    // The priority of our packet processor.
    private static final int PROCESSOR_PRIORITY = 128;
    // Is the window of time in which an attack flow is considered as active.
    private static final int ATTACK_TIMEOUT = 90;
    // Is the threshold of the number of attack flows that
    // a host must receive in order to take action and block the attackers.
    private static final int ATTACK_THRESHOLD = 1;
    // Is the time to live of a flow rule that blocks an attacker, because we don't want to block forever that host.
    private static final int FLOW_RULE_TIME = 5 * 60; // seconds

    private static final int DROP_PRIORITY = 129;
    private static final int TIMEOUT_SEC = 60;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new TcpPacketProcessor();

    // Selector for TCP traffic that is to be intercepted
    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).matchIPProtocol(IPv4.PROTOCOL_TCP)
            .build();

    private Classifier classifier;
    private FlowApi flowApi;

    // Holds the current active flows
    private static final ConcurrentHashMap<FlowKey, FlowData> flows = new ConcurrentHashMap<>();

    // Holds the current blocked flows
    private static final ConcurrentHashMap<AttackKey, FlowRuleId> blockedAttacks = new ConcurrentHashMap<>();

    // Holds the current detected attack flows that aren't blocked
    private static final ConcurrentHashMap<DistributedAttackKey, LinkedList<FlowData>> attackFlows =
            new ConcurrentHashMap<>();


    private static final Multimap<MacAddress, PingRecord> pings = Multimaps.synchronizedMultimap(HashMultimap.create());
    private static final Timer timer = new Timer("oneping-sweeper");

    private static final ConcurrentHashMap<MacAddress, Long> pendingFlows =
            new ConcurrentHashMap<>();
            ; // Flow chưa hoàn thành cùng thời điểm nhận
    private static final long FLOW_TIMEOUT = 30; // Thời gian tối đa (giây) để flow phải kết thúc

    private static final ConcurrentHashMap<MacAddress, Long> pendingFlowsCount =
            new ConcurrentHashMap<>();// Flow chưa hoàn thành cùng thời điểm nhận
    private static final long MAX_ALLOW = 30; // Thời gian tối đa (giây) để flow phải kết thúc


    /**.
     * Runs when the application is started, after activation or reinstall
     */
    @Activate
    protected void activate() {
        // Register application to get an app id
        appId = coreService.registerApplication("org.onos.httpddosdetector", () -> log.info("Periscope down."));

        // Adds packet processor with CONTROL priority which is a high priority
        // that allows to control traffic.
        packetService.addProcessor(packetProcessor, PROCESSOR_PRIORITY);
        packetService.requestPackets(intercept, PacketPriority.CONTROL, appId,
                Optional.empty());
        // TODO(abrahamtorres): Check if the performance of the controller is affected by using
        // CONTROL priority, if it affects then change it to REACTIVE priority

        // Initialize the classifier and load the model to be used
        classifier = new RandomForestBinClassifier();
        classifier.Load("/models/model.json");

        // Initialize the flow api to communicate with the rest api
        flowApi = new FlowApi(appId);

        log.info("HTTP DDoS detector started");
    }

    /**.
     * Runs on when application is stopped, when unistalled or deactivated
     */
    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flows.clear();
        blockedAttacks.clear();
        attackFlows.clear();
        log.info("HTTP DDoS detector stopped");
    }
    private void banPings(DeviceId deviceId, MacAddress src, MacAddress dst) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(src).matchEthDst(dst).build();
        TrafficTreatment drop = DefaultTrafficTreatment.builder()
                .drop().build();

        flowObjectiveService.forward(deviceId, DefaultForwardingObjective.builder()
                .fromApp(appId)
                .withSelector(selector)
                .withTreatment(drop)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .withPriority(DROP_PRIORITY)
                .makeTemporary(TIMEOUT_SEC)
                .add());
    }
    /**.
     * Processes the provided TCP packet
     * @param context packet context
     * @param eth ethernet packet
     */
    String[] macSwitch = { "D2:21:93:B7:84:34",
                            "C6:29:CC:08:14:29",
                            "86:62:DA:A5:72:FE",
                            "9A:6C:7C:D1:F7:97",
                            "8A:72:56:11:15:0F"};
    private synchronized void processPacket(PacketContext context, Ethernet eth) {
        // Get identifiers of the packet
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) eth.getPayload();
        int srcip = ipv4.getSourceAddress();
        int dstip = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        TCP tcp = (TCP) ipv4.getPayload();
        int srcport = tcp.getSourcePort();
        int dstport = tcp.getDestinationPort();

        MacAddress src = eth.getSourceMAC();
        MacAddress dst = eth.getDestinationMAC();
        PingRecord ping = new PingRecord(src, dst);
        boolean pinged = pings.get(src).contains(ping);

        if (pinged) {
            banPings(deviceId, src, dst);
            context.block();
            pendingFlows.remove(src);
            pendingFlowsCount.remove(src);
            pendingFlows.remove(dst);
            pendingFlowsCount.remove(dst);
            return;
        }

        if(pendingFlows.containsKey(src) || pendingFlowsCount.containsKey(src)) {
            long currentTime = System.currentTimeMillis();
            long startTime = pendingFlows.get(src);
            long countPending = pendingFlowsCount.get(src);

            if ((currentTime - startTime) / 1000 > FLOW_TIMEOUT ||
                countPending > MAX_ALLOW
            ){
                log.warn("Detected attack flow");
                pings.put(src, ping);
                timer.schedule(new PingPruner(src, ping),  TIMEOUT_SEC *1000);
                banPings(deviceId, src, dst);
                context.block();
                pendingFlows.remove(src);
                pendingFlowsCount.remove(src);
                pendingFlows.remove(dst);
                pendingFlowsCount.remove(dst);
                return;
            }

            pendingFlowsCount.put(src, countPending+1);
        }

        if(!pendingFlows.containsKey(src) && !pendingFlowsCount.containsKey(src) &&
                !Arrays.asList(macSwitch).contains(src.toString())
        ){
            pendingFlows.put(src, System.currentTimeMillis());
            pendingFlowsCount.put(src, 0L);
            timer.schedule(new RecordPruner(src), TIMEOUT_SEC *1000)    ;
        }

        // Calculate forward and backward keys
        FlowKey forwardKey = new FlowKey(srcip, srcport, dstip, dstport, proto);
        FlowKey backwardKey = new FlowKey(dstip, dstport, srcip, srcport, proto);
        FlowData f;

        // Check if flow is stored
        if (flows.containsKey(forwardKey) || flows.containsKey(backwardKey)) {
            // Get corresponding flow and update it
            if (flows.containsKey(forwardKey)) {
                f = flows.get(forwardKey);
            } else {
                f = flows.get(backwardKey);
            }
            f.Add(eth, srcip);
            // Calling export will generate a log of the updated flow features
            f.Export();

        } else {
            // Add new flow
            f = new FlowData(srcip, srcport, dstip, dstport, proto, eth);
            // Include forward and backward keys
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
        }

        // If connection is closed
        if (f.IsClosed()) {
            pendingFlows.remove(src);
            pendingFlows.remove(dst);
            pendingFlowsCount.remove(src);
            pendingFlowsCount.remove(dst);
            log.info("Close {} {} {} {}", src, dst, pendingFlows, pendingFlowsCount);

            if(f.ToArrayList()==null){
                pings.put(src, ping);
                timer.schedule(new PingPruner(src, ping), TIMEOUT_SEC * 1000);
                return;
            }
            // Pass through classifier
            RandomForestBinClassifier.Class flowClass = RandomForestBinClassifier.Class.valueOf(classifier.Classify(f));
            // React depending on the result
            switch (flowClass) {
                case NORMAL:
                    log.info("Detected normal flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})",
                            f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    break;
                case ATTACK:
                    log.warn("Detected attack flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})",
                            f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    // Add attack to the proper queue
                    LinkedList<FlowData> attackFlowsQueue;
                    DistributedAttackKey k = f.forwardKey.toDistributedAttackKey();
                    if (attackFlows.containsKey(k)) {
                        attackFlowsQueue = attackFlows.get(k);
                    } else {
                        attackFlowsQueue = new LinkedList<FlowData>();
                        attackFlows.put(k, attackFlowsQueue);
                    }
                    attackFlowsQueue.add(f);
                    pings.put(src, ping);
                    timer.schedule(new PingPruner(src, ping),  TIMEOUT_SEC *1000);
                    break;
                case ERROR:
                    log.error("Error predicting flow, Key(srcip: {}, srcport: {}, dstip: {}, dstport: {}, proto: {})",
                            f.srcip, f.srcport, f.dstip, f.dstport, f.proto);
                    break;
                default:
                    break;

            }
            // Delete from flows, since it is closed we don't expect any other packet from this flow
            flows.remove(forwardKey);
            flows.remove(backwardKey);
            f = null;
        }

        long currTimeInSecs = System.currentTimeMillis() / 1000;
        attackFlows.forEach((distAttackKey, attackQueue) -> {
            // Remove expired attack flows
            while (attackQueue.peek().flast + ATTACK_TIMEOUT < currTimeInSecs) {
                attackQueue.remove();
            }
            // Check if host is under attack
            if (attackQueue.size() > ATTACK_THRESHOLD) {
                // Check if attacker is not already blocked
                for (FlowData attack : attackQueue) {
                    AttackKey attackKey = attack.forwardKey.toAttackKey();
                    // If attacker isn't already blocked
                    if (!blockedAttacks.containsKey(attackKey)) {
                        // Add flow rule to block attack
                        ApiResponse res = addFlowRule(deviceId, attackKey);
                        if (!res.result) {
                            log.warn("Failed to add flow rule, Key(srcip: {}, dstip: {}, dstport: {})",
                                    attack.srcip, attack.dstip, attack.dstport);
                            continue;
                        }
                        // Read response from the api
                        String body = res.response.readEntity(String.class);
                        JsonNode apiRes = null;
                        try {
                            ObjectMapper mapper = new ObjectMapper();
                            apiRes = mapper.readTree(body);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        if (apiRes == null) {
                            log.warn("Failed to add flow rule, Key(srcip: {}, dstip: {}, dstport: {})",
                                    attack.srcip, attack.dstip, attack.dstport);
                            continue;
                        }

                        // Retrieve flowId and deviceId from the response, so we can later delete the flow rule
                        JsonNode newFlowRule = apiRes.get("flows").get(0);
                        FlowRuleId rule = new FlowRuleId(newFlowRule.get("deviceId").asText(),
                                newFlowRule.get("flowId").asText());
                        blockedAttacks.put(attackKey, rule);
                        log.info("Added flow rule to block attack, Key(srcip: {}, dstip: {}, dstport: {})",
                                attack.srcip, attack.dstip, attack.dstport);
                    }
                    // Attacker is already blocked, no need to store the attacks
                    attackQueue.remove(attack);
                }
            }

            // Remove empty attack queues
            if (attackQueue.size() == 0) {
                attackFlows.remove(distAttackKey);
            }
        });

        // TODO(abrahamtorres): Remove expired flow rules
    }
    private class PingRecord {
        private final MacAddress src;
        private final MacAddress dst;

        PingRecord(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            final PingRecord other = (PingRecord) obj;
            return Objects.equals(this.src, other.src) && Objects.equals(this.dst, other.dst);
        }
    }

    private class PingPruner extends TimerTask {
        private final MacAddress src;
        private final PingRecord ping;

        public PingPruner(MacAddress src, PingRecord ping) {
            this.src = src;
            this.ping = ping;
        }

        @Override
        public void run() {
            pings.remove(src, ping);
        }
    }

    private class RecordPruner extends TimerTask {
        private final MacAddress src;

        public RecordPruner(MacAddress src) {
            this.src = src;
        }

        @Override
        public void run() {
            pendingFlows.remove(src);
            pendingFlowsCount.remove(src);
        }
    }


    /**.
     * Add flow rule to block an attacker
     * @param deviceId Device that will receive the flow rule
     * @param attackKey Identifier of the attack
     * @return Flow api response
     */
    private ApiResponse addFlowRule(DeviceId deviceId, AttackKey attackKey) {
        // Build flow rule object
        ObjectNode flowRequest = new ObjectNode(JsonNodeFactory.instance);

        ObjectNode flow = new ObjectNode(JsonNodeFactory.instance);
        flow.put("priority", 40000);
        flow.put("timeout", 0);
        flow.put("isPermanent", true);
        flow.put("deviceId", deviceId.toString());

        ObjectNode selector = flow.putObject("selector");

        ArrayNode criteria = selector.putArray("criteria");
        // Match TCP packets
        criteria.addObject()
                .put("type", "IP_PROTO")
                .put("protocol", "0x05");
        // Match TCP destination port of the attacked host
        criteria.addObject()
                .put("type", "TCP_DST")
                .put("tcpPort", attackKey.dstport);
        // Match destination ip of the attacked host
        IpPrefix dstIpPrefix = IpPrefix.valueOf(attackKey.dstip, IpPrefix.MAX_INET_MASK_LENGTH);
        criteria.addObject()
                .put("type", "IPV4_DST")
                .put("ip", dstIpPrefix.toString());
        // Match source ip
        IpPrefix srcIpPrefix = IpPrefix.valueOf(attackKey.srcip, IpPrefix.MAX_INET_MASK_LENGTH);
        criteria.addObject()
                .put("type", "IPV4_SRC")
                .put("ip", srcIpPrefix.toString());


        ArrayNode flows = flowRequest.putArray("flows");

        flows.add(flow);

        return this.flowApi.postFlowRule(flowRequest);
    }

    /**
     * Indicates whether the specified packet corresponds to TCP packet.
     * @param eth packet to be checked
     * @return true if the packet is TCP
     */
    private boolean isTcpPacket(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP;
    }

    /**.
     * Packet processor implementation, will call processPacket() for every TCP packet received
     */
    private class TcpPacketProcessor implements PacketProcessor {

        @Override
        public synchronized void process(PacketContext context) {

            Ethernet packet = context.inPacket().parsed();
            if (packet == null) {
                return;
            }

            if (isTcpPacket(packet)) {
                processPacket(context, packet);
            }
        }
    }
}
