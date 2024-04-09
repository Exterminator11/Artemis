import csv
from collections import defaultdict
import json

import requests
from scapy.sessions import DefaultSession

from sklearn.preprocessing import MinMaxScaler,QuantileTransformer

import pandas as pd

# from .features.context.packet_direction import PacketDirection
# from .features.context.packet_flow_key import get_packet_flow_key
# from .flow import Flow

from features.context.packet_direction import PacketDirection
from features.context.packet_flow_key import get_packet_flow_key
from flow import Flow

import socketio
import warnings
import numpy as np
import random
import time

warnings.filterwarnings('ignore')
sio=socketio.Client()

@sio.event
def connect():
    print('Connected to server')

@sio.event
def disconnect():
    print('Disconnected from server')

@sio.event
def send_data(data):
    sio.emit('data_event', data)

@sio.on('response_event')
def receive_data(data):
    print('Received data:', data)

sio.connect('http://localhost:8000',wait_timeout=10)

EXPIRED_UPDATE = 40
# MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 10000


class FlowSession(DefaultSession):

    """Creates a list of network flows."""

    def __init__(self,*args, **kwargs):#, *args, **kwargs
        self.flows = {}
        # self.csv_line = 0

        # if self.output_mode == "flow":
        #     output = open(self.output_file, "w")
        #     self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)#, *args, **kwargs

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        # if self.output_mode != "flow":
        #     if "TCP" not in packet:
        #         return
        #     elif "UDP" not in packet:
        #         return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            if flow is None:
                # If no flow exists create a new flow
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                # If the packet exists in the flow but the packet is sent
                # after too much of a delay than it is a part of a new flow.
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:

                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        flow.add_packet(packet, direction)

        # if not self.url_model:
        #     GARBAGE_COLLECT_PACKETS = 10000

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120
        ):
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        if True:#not self.url_model
            print("Garbage Collection Began. Flows = {}".format(len(self.flows)))
        keys = list(self.flows.keys())
        # l=[]
        for k in keys:
            flow = self.flows.get(k)

            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):
                # data=flow.get_data()
                # l.extend(list(data.values()))


                # data=flow.get_data()
                # false_attacks={'DOS_goldeneye':[80.0, 6.0, 6010454.0, 0.6655071314, 0.6655071314, 4.0, 4.0, 285.0, 972.0, 285.0, 0.0, 71.25, 142.5, 972.0, 0.0, 243.0, 486.0, 972.0, 0.0, 139.6666666667, 326.0460090233, 106306.0, 136.0, 136.0, 32.0, 1.0, 858636.285714286, 5004855.0, 6.0, 1865827.78746456, 1005599.0, 1000372.0, 316.0, 335199.666666667, 576060.720133159, 6010448.0, 5005181.0, 5229.0, 2003482.66666667, 2646706.61386417, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 157.125, 26883.0, 219.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 71.25, 243.0, 0.0, 4.0, 4.0, 285.0, 972.0],
                #                'DOS_slowloris':[80.0, 6.0, 3863707.0, 2.0705503808, 0.5176375952, 8.0, 2.0, 920.0, 0.0, 230.0, 0.0, 115.0, 122.9401712797, 0.0, 0.0, 0.0, 0.0, 230.0, 0.0, 83.6363636364, 116.0407451952, 13465.4545454545, 280.0, 72.0, 32.0, 4.0, 429300.777777778, 2016118.0, 4.0, 680073.10420439, 3863702.0, 2016118.0, 520.0, 551957.428571429, 733267.666337438, 831937.0, 831937.0, 831937.0, 831937.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 92.0, 26883.0, 219.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 115.0, 0.0, 0.0, 8.0, 2.0, 920.0, 0.0],
                #                'Brute-force-Web':[80.0, 6.0, 5821967.0, 0.5152897638, 0.1717632546, 3.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 72.0, 32.0, 20.0, 0.0, 1940655.66666667, 5821633.0, 15.0, 3361024.9656153, 5821967.0, 5821633.0, 334.0, 2910983.5, 4116279.99821447, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 8192.0, 26883.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 3.0, 1.0, 0.0, 0.0]}
                # attack_type=random.choice(list(false_attacks.keys()))
                # false_data=false_attacks[attack_type]
                # number=random.choice([0,1])
                # if(number==0):
                #     d={'data':false_data,'src_ip':'0.0.0.0','dst_ip':'0.0.0.0','dst_port':false_data[0]}
                #     print(f'false_data:{attack_type}')
                #     send_data(d)
                # else:
                #     print('Normal')
                #     data = flow.get_data()
                #     data=list(data.values())
                #     src_ip=data.pop(0)
                #     dst_ip=data.pop(0)
                #     src_port=data.pop(0)
                #     dst_port=data.pop(0)
                #     data=[float(i) for i in data]
                #     full_data=({'src_ip':src_ip,'dst_ip':dst_ip,'dst_port':dst_port,'src_port':src_port,'data':data})
                #     send_data(full_data)
                # print('Sent data waiting to process')
                # time.sleep(3)


                print('Normal')
                data = flow.get_data()
                data=list(data.values())
                src_ip=data.pop(0)
                dst_ip=data.pop(0)
                src_port=data.pop(0)
                dst_port=data.pop(0)
                data=[float(i) for i in data]
                full_data=({'src_ip':src_ip,'dst_ip':dst_ip,'dst_port':dst_port,'src_port':src_port,'data':data})
                send_data(full_data)
                print('Sent data waiting to process')
                time.sleep(3)

                # print('Normal')
                # data = flow.get_data()
                # data=list(data.values())
                # data.pop(0)
                # data.pop(0)
                # data.pop(0)
                # data.pop(2)
                # data.pop(3)
                # data.pop(3)
                # data=[float(i) for i in data]
                # send_data(data)
                # print('Sent data waiting to process')

                # print('Sent data waiting to process')
                # if self.url_model:
                #     payload = {
                #         "columns": list(data.keys()),
                #         "data": [list(data.values())],
                #     }
                #     post = requests.post(
                #         self.url_model,
                #         json=payload,
                #         headers={
                #             "Content-Type": "application/json; format=pandas-split"
                #         },
                #     )
                #     resp = post.json()
                #     result = resp["result"].pop()
                #     if result == 0:
                #         result_print = "Benign"
                #     else:
                #         result_print = "Malicious"

                #     print(
                #         "{: <15}:{: <6} -> {: <15}:{: <6} \t {} (~{:.2f}%)".format(
                #             resp["src_ip"],
                #             resp["src_port"],
                #             resp["dst_ip"],
                #             resp["dst_port"],
                #             result_print,
                #             resp["probability"].pop()[result] * 100,
                #         )
                #     )

                # if self.csv_line == 0:
                #     self.csv_writer.writerow(data.keys())

                # self.csv_writer.writerow(data.values())
                # self.csv_line += 1

                del self.flows[k]
        # if not self.url_model:
        if True:
            print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))


# def generate_session_class(output_mode, output_file, url_model):
#     return type(
#         "NewFlowSession",
#         (FlowSession,),
#         {
#             "output_mode": output_mode,
#             "output_file": output_file,
#             "url_model": url_model,
#         },
#     )

#My fix
def generate_session_class():
    return type(
        "NewFlowSession",
        (FlowSession,),
        {}
    )