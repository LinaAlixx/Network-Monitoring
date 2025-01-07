
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
import socket
import datetime
import matplotlib.pyplot as plt
from collections import defaultdict
from scapy.sendrecv import sniff

# Data structures to store network data
event_data = {"Ethernet": [], "TCP": [], "UDP": []} #Tracks the size of packets per protocol
throughput_data = defaultdict(int) #Tracks the throughput (data volume) per protocol
throughput_history = defaultdict(list)  # To store throughput over time
time_history = []  # Stores timestamps for throughput calculations
latency_data = {} # Stores the start and end time for latency calculations
unique_ips = set() # Tracks unique IP addresses
unique_macs = set() # Tracks unique MAC addresses
packet_count = defaultdict(int) # Tracks the number of packets per protocol
connection_rate_data = defaultdict(list) # Stores timestamps for connection rate
exit_flag = threading.Event() # Flag used to stop sniffing and server threads

# Server configuration
server_IP = '127.0.0.1' # IP address of the server(local host)
server_port = 5000 # Port number to listen on for incoming TCP connections
client_connections = []  # Stores active client connections

# Handles communication with a connected client
def handle_client_connection(client_socket):
    client_connections.append(client_socket) # Add client socket to the list

#Initializes a TCP socket, listens for connections, and spawns threads for each client.
def start_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create TCP socket
    server.bind((server_IP, server_port)) # Bind to IP and port
    server.listen(5)  # Start listening for connections (up to 5 clints)
    print(f"Server listening on {server_IP}:{server_port}")
    try:
        while not exit_flag.is_set():
            client_socket, addr = server.accept() # Accept client connection
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket,)) # create thread
            client_thread.start() # start the thread
    except KeyboardInterrupt:
        exit_flag.set() # Set exit flag to stop when user enter ctrl+c

    finally:
        for conn in client_connections:
            conn.close() # Close all client connections
        server.close() # Close the server socket

# Logging system to store network events to a log file
def log_event(protocol, src_add, dest_add, msg_size, ports=None, flags=None):
    timestamp = datetime.datetime.now() # Current timestamp for logging
    log_msg = (
        f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {protocol} - Source: {src_add}, Destination: {dest_add}, "
        f"Size: {msg_size} bytes"
    )
    #if there are ports or flags add them
    if ports:
        log_msg += f", Ports: {ports}"
    if flags:
        log_msg += f", Flags: {flags}"
    log_msg += "\n"

    #Create log file if does not exit
    log_file = open("network_events.log", "w")
    log_file.write(log_msg)
    log_file.close()

    update_event_data(protocol, src_add, dest_add, msg_size, timestamp) # Update data structures with new event

# Updates the event data dictionary and unique address sets
def update_event_data(protocol, src_add, dest_add, msg_size, timestamp):
    event_data[protocol].append(msg_size) # Store packet size for the protocol
    throughput_data[protocol] += msg_size # Add packet size to throughput data
    packet_count[protocol] += 1 # Increment packet count for protocol
    if protocol == "Ethernet":
        unique_macs.add(src_add) # Add source MAC address to unique MAC set
    else:
        unique_ips.add(src_add) # Add source IP address to unique IP set

    conn_key = (src_add, dest_add) # Create a unique key for the connection (source, destination)
    if protocol in ["TCP", "UDP"]:
        if conn_key not in latency_data:
            latency_data[conn_key] = {"start": timestamp} # Store start time for latency calculation
            connection_rate_data[protocol].append(timestamp) # Store timestamp for connection rate
        else:
            latency_data[conn_key]["end"] = timestamp # Store end time for latency calculation
    elif protocol == "Ethernet":
        connection_rate_data[protocol].append(timestamp)  # Store Ethernet connection timestamp


# Process each captured packets
def process_packet(packet):
    if exit_flag.is_set():
        return False # Stop packet processing if exit flag is set
    message_size = len(packet) # Get size of the packet

     # If the packet is an Ethernet frame, log the Ethernet event
    if packet.haslayer(Ether):
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        log_event("Ethernet", eth_src, eth_dst, message_size)

    # If the packet is an IP packet, log the IP event
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst

        # If the packet contains TCP data, log the TCP event
        if packet.haslayer(TCP):
            tcp_src = packet[TCP].sport
            tcp_dst = packet[TCP].dport
            flags = packet[TCP].flags
            log_event("TCP", src_ip, dest_ip, message_size, ports=(tcp_src, tcp_dst), flags=flags)

        # If the packet contains UDP data, log the UDP event
        elif packet.haslayer(UDP):
            udp_src = packet[UDP].sport
            udp_dst = packet[UDP].dport
            log_event("UDP", src_ip, dest_ip, message_size, ports=(udp_src, udp_dst))

# Start packet sniffing
def start_sniffing():
    print("Starting packet sniffing...\n")
    sniff(filter="ip or tcp or udp", prn=process_packet, store=0, stop_filter=lambda x: exit_flag.is_set())

# Display network statistics such as connection count, average size, and unique addresses
def display_statistics():
    print("\n--- Network Statistics ---")
    for protocol, sizes in event_data.items(): #calculate number of connections and average size of packets
        num_connections = len(sizes)
        avg_size = sum(sizes) / num_connections if num_connections else 0
        print(f"{protocol} Connections: {num_connections}, Average Size: {avg_size:.2f} bytes")

    # Show the rate of new connections over the last 30 seconds
    connection_rate_interval = 30
    current_time = datetime.datetime.now()
    for protocol, timestamps in connection_rate_data.items():
        recent_connections = [t for t in timestamps if (current_time - t).total_seconds() <= connection_rate_interval]
        print(f"Rate of New Connections ({protocol}): {len(recent_connections)} connections")

    print(f"Unique IP Addresses: {len(unique_ips)}")
    print(f"Unique MAC Addresses: {len(unique_macs)}")
    print("----------------------------\n")

#  Calculate and plot latency average for all protcols
def cal_and_plot_latency():
    latencies = []  # List to store latency values
    for conn_key, times in latency_data.items():
        if "start" in times and "end" in times:
            latency = (times["end"] - times["start"]).total_seconds() * 1000  # Convert to milliseconds
            latencies.append(latency)

    # calculate latency averge
    avg_latensy = sum(latencies) / len(latencies)

    if latencies:
        # Plot Latency Distribution using Histogram
        plt.figure(figsize=(10, 6))
        plt.title("Latency Average")
        plt.ylabel("Average latency")
        plt.bar('All Protocols', avg_latensy)
        plt.grid(True)
        plt.show()
    else:
        print("No latency data available.")


#  Calculate throughput (data volume per time interval) and plot the results
def cal_and_plot_throughput(interval=10):
    print("------------------------")
    print("Throughput (bps):")
    time_history.append(datetime.datetime.now())  # Track the current time
    for protocol, bytes_count in throughput_data.items():
        throughput_bps = (bytes_count * 8) / interval # Convert bytes to bits and calculate throughput
        print(f"{protocol}: {throughput_bps:.2f} bps")
        throughput_history[protocol].append(throughput_bps) # Store throughput history
        throughput_data[protocol] = 0 # Reset throughput data for the next interval
    print("------------------------\n")

    # Plot Throughput Over Time
    plt.figure(figsize=(12, 6))
    for protocol, history in throughput_history.items():
        plt.plot(time_history, history, label=f"{protocol} Throughput")
    plt.title("Throughput Over Time")
    plt.xlabel("Time")
    plt.ylabel("Throughput (bps)")
    plt.legend()
    plt.grid(True)
    plt.show()

# Protocol Usage graph
def plot_protocol_usage():
    # Create a bar chart for Protocol Usage
    protocols = ['Ethernet', 'TCP', 'UDP']
    packet_counts = [len(event_data[protocol]) for protocol in protocols]
    ip_count = len(unique_ips)
    mac_count = len(unique_macs)

    # graph details such as colors and titles
    plt.figure(figsize=(10, 6))
    plt.bar(protocols, packet_counts, color='blue', edgecolor='black', label='Packets per Protocol')
    plt.bar('IP Addresses', ip_count, color='red', edgecolor='black', label='Unique IPs')
    plt.bar('MAC Addresses', mac_count, color='green', edgecolor='black', label='Unique MACs')
    plt.title("Protocol Usage and Unique IP/MAC Counts")
    plt.xlabel("Protocol / Address Type")
    plt.ylabel("Count")
    plt.legend()
    plt.grid(True)
    plt.show()

# all components, including starting threads, displaying statistics, and handling user termination.
def main():
    #create and start the threads
    tcp_server_thread = threading.Thread(target=start_tcp_server, daemon=True).start()
    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True).start()

    while not exit_flag.is_set():
        try: #every 30 sec display the statistucs and the 3 graphs
            time.sleep(30)
            display_statistics()
            cal_and_plot_throughput()
            cal_and_plot_latency()
            plot_protocol_usage()

        except KeyboardInterrupt: #Ctrl+c display final statistics and termminate the program
            exit_flag.set()  # Signal the sniffing thread to stop
            print("\nCtrl+C detected!")
            print(" ****  This is the final statistics   ****")
            display_statistics() # Display the final statistics
            print("\nShutting down...")

        # Ensure all threads exit cleanly
        if tcp_server_thread is not None and tcp_server_thread.is_alive():
            tcp_server_thread.join()
        if sniffing_thread is not None and sniffing_thread.is_alive():
            sniffing_thread.join()

    print("Program terminated gracefully.")

if __name__ == "__main__":
    main()
