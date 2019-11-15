# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv6
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
from ryu.app import simple_switch_13



class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']
        self.id_sw =  [] #ide de los sw
        self.lista_sw = []
        self.enlaces = {}
        self.grafo = {}
        self.topology_api = self
        self.net = nx.DiGraph()
        self.a = 0
        self.asit = []
        self.BW = [1, 5, 1, 1, 1, 5, 1, 1]
        self.match = []
        self.pru = []
        self.pru = [1, 2]
        

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000004'):
                  {'bridge': {'priority': 0xb000}}}
        self.stp.set_config(config)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    def Dijkstra(self, grafo, start, end):
        shortest_distance = {}
        predecesor = {}
        UnseenNode = self.grafo # se inicia de esta manera por que no se conoce ninguna nodo dede el principio
        print UnseenNode
        infinity = 99999999999999
        path = [] 
        for node in UnseenNode:
            shortest_distance[node] = infinity
        shortest_distance[start] = 0 #como sabe que start es 'a'
                
        while UnseenNode:
            print ('entro')
            #verifica que el punto de partida tenga el menor coste del nodo. El cual se lo asigna
            # a minNode. 
            minNode = None
            for node in UnseenNode:
                if minNode is None:
                    minNode = node
                elif shortest_distance[node] < shortest_distance[minNode]:
                    minNode = node
            
            for childNode, weight in self.grafo[minNode].items():             
                if weight +  shortest_distance[minNode] < shortest_distance[childNode]:
                    shortest_distance[childNode] = weight + shortest_distance[minNode]
                    predecesor[childNode] = minNode
            UnseenNode.pop(minNode)
        print (shortest_distance)

        currentNode = end

        while currentNode != start:
            try:
                path.insert(0, currentNode)
                currentNode = predecesor[currentNode]
            except KeyError:
                print ('patch no reachable')
                break
        path.insert(0, start)
        if shortest_distance[end] != infinity:
            print ('shortest distance is ' + str(shortest_distance[end]))
            self.pru = str(path)
            print ('path is ' + str(path))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
         
        
        id_switch =datapath.id #id del switch en cuestion
        self.id_sw.append(id_switch) #Vector de SW
        ultimo = self.id_sw
        #print self.id_sw #Vector de SW
     
        self.grafo.setdefault(ultimo.pop(), {})
        print self.grafo        
        
        

        match = parser.OFPMatch()
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)  


    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        eth_type = eth.ethertype                

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        
        
        if eth_type == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            protocol = ip.proto            
            print('protocolo num {}'.format(protocol))
            print("source "+srcip)
            print("destino "+dstip)
            #print 'paquete {}'.format(pkt)
            if protocol == in_proto.IPPROTO_ICMP:
                src_icmp = eth.src
                dst_icmp = eth.dst
                print ('Paquete ICMP')
                print 'origen imcp {}'.format(src_icmp)
                print 'destino imcp {}'.format(dst_icmp)
                
                if srcip == '10.0.0.1' or srcip == '10.0.0.2':
                    print ('entro para enrutar')
                    for i in range(len(self.mac_to_port)):
                        j = i + 1
                        mac_en_host_src = self.mac_to_port[j].get(src_icmp)                                        
                        if mac_en_host_src == 1:
                            print 'este es el id del sw para el src {}'.format(j)
                            nodo_ini = j                            
                            break
                    for i in range(len(self.mac_to_port)):
                        print ('entro al otro for del dst')
                        j = i + 1                    
                        mac_en_host_dst = self.mac_to_port[j].get(dst_icmp)                    
                        if mac_en_host_dst == 1:
                            print 'este es el id del sw para el dst {}'.format(j)
                            nodo_dst = j                            
                            break
                    print ('nodo inicial {}'.format(nodo_ini))
                    print ('nodo final {}'.format(nodo_dst))
                    n_pares = (srcip, dstip)                    
                    print (n_pares)
                    if n_pares not in self.match:
                        self.match.append(n_pares)
                        print('enruto')
                        self.Dijkstra(self.grafo, nodo_ini, nodo_dst)                                
                    else:
                        print('ya tiene esta ruta')                
    

            elif protocol == in_proto.IPPROTO_UDP:
                src_udp = eth.src
                dst_udp = eth.dst

                if srcip == '10.0.0.1' or srcip == '10.0.0.2':
                    print ('entro para enrutar')
                    for i in range(len(self.mac_to_port)):
                        j = i + 1
                        mac_en_host_src = self.mac_to_port[j].get(src_udp)                                        
                        if mac_en_host_src == 1:
                            print 'este es el id del sw para el src {}'.format(j)
                            nodo_ini = j                            
                            break
                    for i in range(len(self.mac_to_port)):
                        print ('entro al otro for del dst')
                        j = i + 1                    
                        mac_en_host_dst = self.mac_to_port[j].get(dst_udp)                    
                        if mac_en_host_dst == 1:
                            print 'este es el id del sw para el dst {}'.format(j)
                            nodo_dst = j                            
                            break
                    print ('nodo inicial {}'.format(nodo_ini))
                    print ('nodo final {}'.format(nodo_dst))
                    n_pares = (srcip, dstip)                    
                    print (n_pares)
                    if n_pares not in self.match:
                        self.match.append(n_pares)
                        print('enruto')
                        self.Dijkstra(self.grafo, nodo_ini, nodo_dst)        
                    else:
                        print('ya tiene esta ruta')

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)        

        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        
        # Show all switches in the topology
        switches_list = get_switch(self.topology_api, None)  
        switches = [switch.dp.id for switch in switches_list]
        self.net.add_nodes_from(switches)
        print('*** List of switches')
        for switch in switches_list:
            print(switch)
    
        # Show all links in the topology
        links_list = get_link(self.topology_api, None)        
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        num_links = len(links)
        self.net.add_edges_from(links)
        print('*** List of links')
        print 'este es el link {}'.format(links)
        print('este es el edges {}'.format(self.net.edges()))                    
        self.a = self.a +1  
        if self.a == 4:
            for i in range(num_links):
                self.asit.append(links[i][0:2])   #el otro list
            print 'este es el otro {}'.format(self.asit)
            self.graph()
        
    def graph(self):
        contador = 0
        for x in range(int(len(self.grafo))):              
            x = x + 1                         
            for i in range(len(self.asit)):                                                    
                if self.asit[i][0] == x:                    
                    self.grafo[x][self.asit[i][1]] = self.BW[contador]        
                    contador = contador + 1 
        print('este es el grafo final {}'.format(self.grafo))
