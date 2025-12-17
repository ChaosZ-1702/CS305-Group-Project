import sys
import select
import struct
import socket
import hashlib
import argparse
import pickle
import time
from typing import Dict, List, Tuple
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.simsocket import SimSocket
import utils.simsocket as simsocket
from utils.peer_context import PeerContext

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

CHUNK_DATA_SIZE = 512 * 1024
MAX_PAYLOAD = 1024
HEADER_FMT = "BBHII"
HEADER_LEN = struct.calcsize(HEADER_FMT)

class PktType:
    WHOHAS = 0
    IHAVE = 1
    GET = 2
    DATA = 3
    ACK = 4
    DENIED = 5

g_context = None
g_received_chunks = {}
g_download_chunks = []
g_sender_info = {}
g_download_state = {}
g_upload_state = {}
g_window_data = {}

def make_packet(packet_type: int, seq_num: int, ack_num: int, payload: bytes) -> bytes:
    header = struct.pack(
        HEADER_FMT,
        packet_type,
        HEADER_LEN,
        socket.htons(HEADER_LEN + len(payload)),
        socket.htonl(seq_num),
        socket.htonl(ack_num),
    )
    return header + payload

def parse_packet(packet: bytes) -> Tuple:
    if len(packet) < HEADER_LEN:
        return None
    
    header = packet[:HEADER_LEN]
    payload = packet[HEADER_LEN:]
    
    pkt_type, header_len, packet_len, seq_num, ack_num = struct.unpack(HEADER_FMT, header)
    packet_len = socket.ntohs(packet_len)
    seq_num = socket.ntohl(seq_num)
    ack_num = socket.ntohl(ack_num)
    
    return (pkt_type, header_len, packet_len, seq_num, ack_num, payload)

def process_download(sock: simsocket.SimSocket, chunk_file: str, output_file: str) -> None:
    global g_download_chunks, g_context
    
    g_download_chunks = []
    
    with open(chunk_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line:
                parts = line.split(" ")
                if len(parts) >= 2:
                    chunk_hash = parts[1]
                    g_download_chunks.append(chunk_hash)
    
    g_context.output_file = output_file
    
    whohas_hashes = bytes()
    for chunk_hash in g_download_chunks:
        whohas_hashes += bytes.fromhex(chunk_hash)
    
    num_chunks = len(g_download_chunks)
    whohas_payload = struct.pack("B", num_chunks) + whohas_hashes
    
    whohas_pkt = make_packet(PktType.WHOHAS, 0, 0, whohas_payload)
    
    for peer_addr in g_context.peers:
        sock.sendto(whohas_pkt, peer_addr)

def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    global g_received_chunks, g_download_chunks, g_sender_info, g_context
    global g_download_state, g_upload_state, g_window_data
    
    # packet, from_addr = sock.recvfrom(MAX_PAYLOAD + HEADER_LEN)
    packet, from_addr = sock.recvfrom(1440)
    parsed = parse_packet(packet)
    if not parsed:
        return
    
    pkt_type, header_len, packet_len, seq_num, ack_num, payload = parsed
    
    if pkt_type == PktType.WHOHAS:
        num_chunks = payload[0]
        chunk_hashes = payload[1:]
        
        my_chunks = []
        for i in range(num_chunks):
            chunk_hash = chunk_hashes[i * 20:(i + 1) * 20].hex()
            if chunk_hash in g_context.has_chunks:
                my_chunks.append(chunk_hash)
        
        if my_chunks:
            ihave_hashes = bytes()
            for chunk_hash in my_chunks:
                ihave_hashes += bytes.fromhex(chunk_hash)
            
            ihave_payload = struct.pack("B", len(my_chunks)) + ihave_hashes
            ihave_pkt = make_packet(PktType.IHAVE, 0, 0, ihave_payload)
            sock.sendto(ihave_pkt, from_addr)
        else:
            denied_pkt = make_packet(PktType.DENIED, 0, 0, b"")
            sock.sendto(denied_pkt, from_addr)
    
    elif pkt_type == PktType.IHAVE:
        num_chunks = payload[0]
        chunk_hashes = payload[1:]
        
        for i in range(num_chunks):
            chunk_hash = chunk_hashes[i * 20:(i + 1) * 20].hex()
            if chunk_hash in g_download_chunks and chunk_hash not in g_received_chunks:
                if chunk_hash not in g_sender_info:
                    g_sender_info[chunk_hash] = from_addr
                    
                    get_payload = bytes.fromhex(chunk_hash)
                    get_pkt = make_packet(PktType.GET, 0, 0, get_payload)
                    sock.sendto(get_pkt, from_addr)
                    
                    g_download_state[chunk_hash] = {
                        "next_seq": 1,
                        "last_ack": 0,
                        "received_data": {},
                        "addr": from_addr,
                        "finished": False,
                        "last_received_time": time.time(),
                    }
    
    elif pkt_type == PktType.GET:
        chunk_hash = payload.hex()
        
        current_count = sum(1 for s in g_upload_state.values() if s.get("active", False))
        max_conn = g_context.max_conn
        if current_count >= max_conn:
            denied_pkt = make_packet(PktType.DENIED, 0, 0, b"")
            sock.sendto(denied_pkt, from_addr)
            return
        
        if chunk_hash in g_context.has_chunks:
            chunk_data = g_context.has_chunks[chunk_hash]
            
            if from_addr not in g_upload_state:
                g_upload_state[from_addr] = {
                    "chunk_hash": chunk_hash,
                    "chunk_data": chunk_data,
                    "cwnd": 1.0,
                    "ssthresh": 64.0,
                    "last_ack_received": 0,
                    "send_times": {},
                    "timeout": 1.0,
                    "estimated_rtt": 0.5,
                    "dev_rtt": 0.25,
                    "dup_acks": {},
                    "in_flight": 0,
                    "active": True,
                    "last_send_time": time.time(),
                    "in_fast_recovery": False,
                }
                
                g_window_data[from_addr] = {
                    "cwnd_history": [1.0],
                    "time_history": [time.time()],
                }
            
            state = g_upload_state[from_addr]
            state["chunk_hash"] = chunk_hash
            state["chunk_data"] = chunk_data
            state["last_ack_received"] = 0
            state["send_times"] = {}
            state["dup_acks"] = {}
            state["active"] = True
            state["in_fast_recovery"] = False
            
            first_payload = chunk_data[0:MAX_PAYLOAD]
            data_header = struct.pack(
                HEADER_FMT,
                PktType.DATA,
                HEADER_LEN,
                socket.htons(HEADER_LEN + len(first_payload)),
                socket.htonl(1),
                0,
            )
            data_pkt = data_header + first_payload
            sock.sendto(data_pkt, from_addr)
            
            state["send_times"][1] = time.time()
            state["last_send_time"] = time.time()
            state["in_flight"] = 1
        else:
            denied_pkt = make_packet(PktType.DENIED, 0, 0, b"")
            sock.sendto(denied_pkt, from_addr)
    
    elif pkt_type == PktType.DATA:
        for chunk_hash, state in g_download_state.items():
            if state["addr"] == from_addr and not state["finished"]:
                state["received_data"][seq_num] = payload
                state["last_received_time"] = time.time()
                
                while state["next_seq"] in state["received_data"]:
                    state["next_seq"] += 1
                
                new_ack = state["next_seq"] - 1
                if new_ack > state["last_ack"]:
                    state["last_ack"] = new_ack
                
                ack_pkt = make_packet(PktType.ACK, 0, state["last_ack"], b"")
                sock.sendto(ack_pkt, from_addr)
                
                total_packets = (CHUNK_DATA_SIZE + MAX_PAYLOAD - 1) // MAX_PAYLOAD
                if state["last_ack"] >= total_packets:
                    full_data = bytes()
                    for i in range(1, total_packets + 1):
                        if i in state["received_data"]:
                            full_data += state["received_data"][i]
                    
                    chunk_hash_computed = hashlib.sha1(full_data).hexdigest()
                    if chunk_hash_computed == chunk_hash:
                        g_received_chunks[chunk_hash] = full_data
                        state["finished"] = True
                        
                        if len(g_received_chunks) == len(g_download_chunks):
                            output_file = g_context.output_file
                            
                            result_dict = {}
                            for ch in g_download_chunks:
                                if ch in g_received_chunks:
                                    result_dict[ch] = g_received_chunks[ch]
                            
                            with open(output_file, "wb") as f:
                                pickle.dump(result_dict, f)
                break
    
    elif pkt_type == PktType.ACK:
        if from_addr not in g_upload_state:
            return
        
        state = g_upload_state[from_addr]
        if not state.get("active", False):
            return
        
        chunk_data = state["chunk_data"]
        total_packets = (len(chunk_data) + MAX_PAYLOAD - 1) // MAX_PAYLOAD
        
        if ack_num > state["last_ack_received"]:
            sample_rtt = None
            if ack_num in state["send_times"]:
                sample_rtt = time.time() - state["send_times"][ack_num]
            
            if sample_rtt is not None:
                alpha = 0.15
                beta = 0.3
                state["estimated_rtt"] = (1 - alpha) * state["estimated_rtt"] + alpha * sample_rtt
                state["dev_rtt"] = (1 - beta) * state["dev_rtt"] + beta * abs(sample_rtt - state["estimated_rtt"])
                state["timeout"] = max(state["estimated_rtt"] + 4 * state["dev_rtt"], 0.5)
            
            state["last_ack_received"] = ack_num
            state["dup_acks"] = {}
            
            for seq in list(state["send_times"].keys()):
                if seq <= ack_num:
                    del state["send_times"][seq]
            
            if state["in_fast_recovery"]:
                state["cwnd"] = state["ssthresh"]
                state["in_fast_recovery"] = False
            elif state["cwnd"] < state["ssthresh"]:
                state["cwnd"] += 1.0
            else:
                state["cwnd"] += 1.0 / state["cwnd"]
            
            if ack_num >= total_packets:
                state["active"] = False
            else:
                window_size = int(state["cwnd"])
                next_seq = state["last_ack_received"] + 1
                
                packets_to_send = []
                for i in range(window_size):
                    seq_to_send = next_seq + i
                    if seq_to_send <= total_packets and seq_to_send not in state["send_times"]:
                        packets_to_send.append(seq_to_send)
                
                for seq_to_send in packets_to_send:
                    left = (seq_to_send - 1) * MAX_PAYLOAD
                    right = min(seq_to_send * MAX_PAYLOAD, len(chunk_data))
                    payload = chunk_data[left:right]
                    
                    data_header = struct.pack(
                        HEADER_FMT,
                        PktType.DATA,
                        HEADER_LEN,
                        socket.htons(HEADER_LEN + len(payload)),
                        socket.htonl(seq_to_send),
                        0,
                    )
                    data_pkt = data_header + payload
                    sock.sendto(data_pkt, from_addr)
                    
                    state["send_times"][seq_to_send] = time.time()
                    state["last_send_time"] = time.time()
                
                state["in_flight"] = len(state["send_times"])
            
            if from_addr in g_window_data:
                g_window_data[from_addr]["cwnd_history"].append(state["cwnd"])
                g_window_data[from_addr]["time_history"].append(time.time())
        
        else:
            if ack_num not in state["dup_acks"]:
                state["dup_acks"][ack_num] = 0
            state["dup_acks"][ack_num] += 1
            
            if state["dup_acks"][ack_num] == 3:
                state["ssthresh"] = max(state["cwnd"] / 2.0, 2.0)
                state["cwnd"] = state["ssthresh"] + 3.0
                state["in_fast_recovery"] = True
                
                next_seq = ack_num + 1
                total_packets = (len(chunk_data) + MAX_PAYLOAD - 1) // MAX_PAYLOAD
                if next_seq <= total_packets:
                    left = (next_seq - 1) * MAX_PAYLOAD
                    right = min(next_seq * MAX_PAYLOAD, len(chunk_data))
                    payload = chunk_data[left:right]
                    
                    data_header = struct.pack(
                        HEADER_FMT,
                        PktType.DATA,
                        HEADER_LEN,
                        socket.htons(HEADER_LEN + len(payload)),
                        socket.htonl(next_seq),
                        0,
                    )
                    data_pkt = data_header + payload
                    sock.sendto(data_pkt, from_addr)
                    
                    state["send_times"][next_seq] = time.time()
                    state["last_send_time"] = time.time()
                
                if from_addr in g_window_data:
                    g_window_data[from_addr]["cwnd_history"].append(state["cwnd"])
                    g_window_data[from_addr]["time_history"].append(time.time())
            
            elif state["dup_acks"][ack_num] > 3:
                state["cwnd"] += 1.0


def process_user_input(sock: simsocket.SimSocket) -> None:
    command, chunk_file, output_file = input().split()
    if command == "DOWNLOAD":
        process_download(sock, chunk_file, output_file)
    else:
        pass


def peer_run(context: PeerContext) -> None:
    global g_context, g_upload_state
    g_context = context
    
    g_context.peers = [(p[1], int(p[2])) for p in g_context.peers]
    
    sock = simsocket.SimSocket(context.identity, (context.ip, context.port), context.verbose)
    
    try:
        while True:
            ready_sockets, _, _ = select.select([sock, sys.stdin], [], [], 0.1)
            
            if sock in ready_sockets:
                process_inbound_udp(sock)
            
            if sys.stdin in ready_sockets:
                process_user_input(sock)
            
            current_time = time.time()
            for peer_addr, state in list(g_upload_state.items()):
                if not state.get("active", False):
                    continue
                
                chunk_data = state["chunk_data"]
                total_packets = (len(chunk_data) + MAX_PAYLOAD - 1) // MAX_PAYLOAD
                timeout = state["timeout"]
                
                if state["send_times"]:
                    min_seq = min(state["send_times"].keys())
                    send_time = state["send_times"][min_seq]
                    
                    if current_time - send_time > timeout:
                        state["ssthresh"] = max(state["cwnd"] / 2.0, 2.0)
                        state["cwnd"] = 1.0
                        state["in_fast_recovery"] = False
                        
                        left = (min_seq - 1) * MAX_PAYLOAD
                        right = min(min_seq * MAX_PAYLOAD, len(chunk_data))
                        payload = chunk_data[left:right]
                        
                        data_header = struct.pack(
                            HEADER_FMT,
                            PktType.DATA,
                            HEADER_LEN,
                            socket.htons(HEADER_LEN + len(payload)),
                            socket.htonl(min_seq),
                            0,
                        )
                        data_pkt = data_header + payload
                        sock.sendto(data_pkt, peer_addr)
                        
                        state["send_times"][min_seq] = current_time
                        state["last_send_time"] = current_time
                        
                        if peer_addr in g_window_data:
                            g_window_data[peer_addr]["cwnd_history"].append(state["cwnd"])
                            g_window_data[peer_addr]["time_history"].append(time.time())
                
                elif state["last_ack_received"] < total_packets:
                    window_size = int(state["cwnd"])
                    next_seq = state["last_ack_received"] + 1
                    
                    packets_to_send = []
                    for i in range(window_size):
                        seq_to_send = next_seq + i
                        if seq_to_send <= total_packets:
                            packets_to_send.append(seq_to_send)
                    
                    for seq_to_send in packets_to_send:
                        left = (seq_to_send - 1) * MAX_PAYLOAD
                        right = min(seq_to_send * MAX_PAYLOAD, len(chunk_data))
                        payload = chunk_data[left:right]
                        
                        data_header = struct.pack(
                            HEADER_FMT,
                            PktType.DATA,
                            HEADER_LEN,
                            socket.htons(HEADER_LEN + len(payload)),
                            socket.htonl(seq_to_send),
                            0,
                        )
                        data_pkt = data_header + payload
                        sock.sendto(data_pkt, peer_addr)
                        
                        state["send_times"][seq_to_send] = current_time
                        state["last_send_time"] = current_time
    
            
            # 检查下载超时,如果超过10秒未收到数据,重新发送WHOHAS
            for chunk_hash, state in list(g_download_state.items()):
                if not state["finished"]:
                    last_time = state.get("last_received_time", 0)
                    if current_time - last_time > 10.0:
                        # 超时,重新寻找发送者
                        if chunk_hash in g_sender_info:
                            del g_sender_info[chunk_hash]
                        
                        # 重置下载状态
                        state["last_received_time"] = current_time
                        
                        # 重新发送WHOHAS
                        whohas_hashes = bytes.fromhex(chunk_hash)
                        whohas_payload = struct.pack("B", 1) + whohas_hashes
                        whohas_pkt = make_packet(PktType.WHOHAS, 0, 0, whohas_payload)
                        for peer_addr in g_context.peers:
                            sock.sendto(whohas_pkt, peer_addr)
    
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()





def plot_cwnd():
    """
    绘制拥塞窗口变化曲线
    """
    if not HAS_MATPLOTLIB:
        print("matplotlib not installed, skipping plot")
        return
    
    global g_window_data
    
    if not g_window_data:
        print("No congestion window data to plot")
        return
    
    try:
        plt.figure(figsize=(12, 6))
        
        for addr, data in g_window_data.items():
            if not data["time_history"] or not data["cwnd_history"]:
                continue
            
            start_time = data["time_history"][0]
            times = [t - start_time for t in data["time_history"]]
            cwnd_values = data["cwnd_history"]
            
            label = f"{addr[0]}:{addr[1]}"
            plt.plot(times, cwnd_values, marker='o', markersize=3, label=label)
        
        plt.xlabel('Time (seconds)')
        plt.ylabel('Congestion Window (packets)')
        plt.title('Congestion Window Evolution')
        plt.legend()
        plt.grid(True)
        
        output_path = 'concurrency_analysis.png'
        plt.savefig(output_path, dpi=100, bbox_inches='tight')
        plt.close()
        
        print(f"Congestion window plot saved to {output_path}")
    
    except Exception as e:
        print(f"Error plotting congestion window: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--identity", type=int, default=0)
    parser.add_argument("-p", "--peer-file", type=str, default="nodes.map")
    parser.add_argument("-c", "--chunk-file", type=str, required=True)
    parser.add_argument("-m", "--max-conn", type=int, default=1)
    parser.add_argument("-v", "--verbose", type=int, default=0)
    parser.add_argument("-t", "--timeout", type=int, default=0)
    args = parser.parse_args()
    
    context = PeerContext(args)
    peer_run(context)


if __name__ == "__main__":
    main()
