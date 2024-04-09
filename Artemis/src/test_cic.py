import socketio
import eventlet
from eventlet import wsgi
import warnings
import pickle
import os
import json
import numpy as np
import os
from sklearn.preprocessing import MinMaxScaler, QuantileTransformer, PowerTransformer
import pandas as pd

current_working_directory = os.getcwd()


import socket


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        return ip_address
    except:
        return "Unable to get IP"


warnings.filterwarnings("ignore")

models = {}

current_working_directory = os.getcwd()

sio = socketio.Server()
app = socketio.WSGIApp(sio)

layer1 = pickle.load(
    open(
        "/Users/rachitdas/Desktop/Artemis.ai/final-a/src/xgb_with_lr01a001l003ne450spw2md8.pkl",
        "rb",
    )
)
layer_2 = []

for i in os.listdir("/Users/rachitdas/Desktop/Artemis.ai/final-a/src/layer2"):
    print(i)
    current_layer = pickle.load(
        open("/Users/rachitdas/Desktop/Artemis.ai/final-a/src/layer2/" + i, "rb")
    )
    models[current_layer] = i[:-4]


@sio.event
def connect(sid, environ):
    print("Client connected:", sid)


@sio.event
def disconnect(sid):
    print("Client disconnected:", sid)


@sio.event
def data_event(sid, data):
    qs = pickle.load(
        open(
            "/Users/rachitdas/Desktop/Artemis.ai/final-a/src/scalar_quantile.pkl", "rb"
        )
    )
    ms = pickle.load(
        open("/Users/rachitdas/Desktop/Artemis.ai/final-a/src/scalar_min_max.pkl", "rb")
    )
    pt = pickle.load(
        open("/Users/rachitdas/Desktop/Artemis.ai/final-a/src/scalar_power.pkl", "rb")
    )
    # ms=MinMaxScaler()
    # pt=PowerTransformer()
    s = ""
    d = {}
    global models
    print("got data")
    if data["src_ip"] == get_ip():
        s = "No attack detected"
    else:
        received_data = np.array(data["data"])
        layer1_indices = [
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            11,
            12,
            13,
            15,
            16,
            17,
            19,
            20,
            21,
            22,
            23,
            24,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
            35,
            36,
            41,
            42,
            43,
            44,
            45,
            46,
        ]
        layer2_indices = [
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
            35,
            36,
            37,
            38,
            39,
            40,
            43,
            44,
            45,
            46,
            47,
            48,
            49,
            50,
            51,
            52,
            53,
            54,
        ]
        layer1_data = received_data[layer1_indices]
        layer1_data = np.insert(layer1_data, 0, data["dst_port"])
        layer1_data = pd.Series(layer1_data)
        layer1_data = layer1_data.replace([np.inf, -np.inf], 100000)
        layer1_data = layer1_data.to_numpy()
        layer1_data = layer1_data.reshape(1, -1)
        layer2_data = received_data[layer2_indices]
        layer1_data = qs.transform(layer1_data)
        pred = layer1.predict(layer1_data)
        if pred == 1:
            for i in models:
                layer2_data1 = pd.Series(layer2_data)
                layer2_data1 = layer2_data1.replace([np.inf, -np.inf], 100000)
                layer2_dataf = (layer2_data1.to_numpy()).reshape(1, -1)
                if models[i] == "dos_hulk":
                    layer2_dataf = ms.transform(layer2_dataf)
                else:
                    layer2_dataf = pt.transform(layer2_dataf)
                pred1 = i.predict(layer2_dataf)
                if pred1 == 1:
                    s += models[i] + " "
            if s == "":
                s = "Probable zero day attack"
        else:
            s = "No attack detected"
    d = {
        "prediction": s,
        "src_ip": data["src_ip"],
        "dst_ip": data["dst_ip"],
        "dst_port": data["dst_port"],
    }
    d = json.dumps(d)
    sio.emit("data_event2", d)


if __name__ == "__main__":
    port = 8000  # Replace with your desired port number
    print(f"Server running on port {port}")
    eventlet.wsgi.server(eventlet.listen(("0.0.0.0", port)), app)
