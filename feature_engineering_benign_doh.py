from scapy.all import *
from datetime import datetime, timedelta
import numpy as np
from collections import Counter
import pandas as pd
from statistics import mode
import pyshark

def extract_flow_bytes_and_time(packets, stream_index):
    time_stamp_sent_packet = {}
    time_stamp_received_packet = {}
    packet_tracker = {}
    flow_bytes_sent = {}
    flow_bytes_received = {}
    flow_start_time_of_sent = {}
    flow_end_time_of_sent = {}
    flow_start_time_of_received = {}
    flow_end_time_of_received = {}
    packet_length_sent = {}
    packet_length_received = {}
    reverse_flow_tracker = {}
    count = 0

    for packet_count, packet in enumerate(packets):
        # Check if the packet has an IP layer
        if IP in packet:
            # Extracting source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extracting source and destination port numbers (for TCP and UDP)
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                continue  # Skip non-TCP and non-UDP packets

            # Construct flow key for outgoing flow
            print(f"packet_count: {packet_count}, stream_index length: {len(stream_index)}")
            flow_key = (src_ip, src_port, dst_ip, dst_port, stream_index[packet_count])
            flow_key_ba = (dst_ip, dst_port, src_ip, src_port, stream_index[packet_count])

            # Extract packet length
            packet_length = len(packet)

            server_ip = ['10.0.2.9']

            # Code to get the received flow bytes
            if src_ip in server_ip:
                # Accumulate bytes for the flow
                if flow_key in flow_bytes_received:
                    flow_bytes_received[flow_key] += packet_length
                else:
                    flow_bytes_received[flow_key] = packet_length


            # Accumulate bytes for the flow
            else:
                if flow_key in flow_bytes_sent:
                    flow_bytes_sent[flow_key] += packet_length
                else:
                    flow_bytes_sent[flow_key] = packet_length
                    reverse_flow_tracker[count] = flow_key_ba
                    count += 1


            # Track the flow and packet.time
            if src_ip in server_ip:
                if flow_key in time_stamp_received_packet:
                    time_stamp_received_packet[flow_key].append(packet_count)
                    packet_tracker[packet_count] = packet.time
                
                else:
                    time_stamp_received_packet[flow_key] = [packet_count]
                    packet_tracker[packet_count] = packet.time

            # Track the time of the sent flow
            else:
                if flow_key in time_stamp_sent_packet:
                    time_stamp_sent_packet[flow_key].append(packet_count)
                    packet_tracker[packet_count] = packet.time

                else:
                    time_stamp_sent_packet[flow_key] = [packet_count]
                    packet_tracker[packet_count] = packet.time

            # Track the start time of the received flow
            if src_ip in server_ip:
                if flow_key not in flow_start_time_of_received:
                    flow_start_time_of_received[flow_key] = packet.time

                # Track the end time of the received flow
                flow_end_time_of_received[flow_key] = packet.time

            # Track the start time of the sent flow
            else:
                if flow_key not in flow_start_time_of_sent:
                    flow_start_time_of_sent[flow_key] = packet.time

                # Track the end time of the sent flow
                flow_end_time_of_sent[flow_key] = packet.time

            # Capture packet length for each received flow
            if src_ip in server_ip:
                if flow_key in packet_length_received:
                    packet_length_received[flow_key].append(packet_length)
                else:
                    packet_length_received[flow_key] = [packet_length]
            
            # Capture packet length for each sent flow
            else:
                if flow_key in packet_length_sent:
                    packet_length_sent[flow_key].append(packet_length)
                else:
                    packet_length_sent[flow_key] = [packet_length]

            
    return reverse_flow_tracker, packet_length_sent, packet_length_received, flow_start_time_of_sent, flow_end_time_of_sent, flow_start_time_of_received, flow_end_time_of_received, flow_bytes_sent, flow_bytes_received, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker


# Calculate flow bytes sent and received
def calculate_flow_byte(flow_bytes_received, flow_bytes_sent, reverse_flow_tracker):
    flow_received = []
    for i in range(len(flow_bytes_sent.keys())):
        if flow_bytes_received.get(reverse_flow_tracker[i]):
            flow_received.append(flow_bytes_received.get(reverse_flow_tracker[i]))
        else:
            flow_received.append(0)
    return flow_bytes_sent, flow_received


def calculate_flow_rate(reverse_flow_tracker, flow_bytes_received, flow_bytes_sent, flow_start_time_of_received, flow_end_time_of_received, flow_start_time_of_sent, flow_end_time_of_sent):
    flow_rate_received = []
    flow_rate_sent = {}
    flow_durations = {}

    # Calculating flow rate sent
    for flow_key, bytes_sent in flow_bytes_sent.items():
        start_time = flow_start_time_of_sent[flow_key]
        end_time = flow_end_time_of_sent[flow_key]

        #print(f'flow key: {flow_key} , bytes sent: {bytes_sent}')  

        # Calculate time period in seconds
        time_period = end_time - start_time
        #print(f'flow key: {flow_key} , time period of sent: {time_period}')

        # Calculate rate of flow bytes sent in bytes per second
        rate = bytes_sent / time_period if time_period > 0 else 0
        flow_rate_sent[flow_key] = round(rate, 6)   

    # Calculating flow rate received
    for i in range(len(flow_bytes_sent.keys())):
        if flow_bytes_received.get(reverse_flow_tracker[i]):
            start_time = flow_start_time_of_received[reverse_flow_tracker[i]]
            end_time = flow_end_time_of_received[reverse_flow_tracker[i]]

            # Calculate time period in seconds
            time_period = end_time - start_time

            # Calculate rate of flow bytes sent in bytes per second
            rate = flow_bytes_received[reverse_flow_tracker[i]] / time_period if time_period > 0 else 0
            flow_rate_received.append(round(rate, 6))
        
        else:
            # Flow rate received not available
            flow_rate_received.append(0)
    
    for i, key in enumerate(flow_start_time_of_sent.keys()):
        start_time = flow_start_time_of_sent[key]
        end_time = flow_end_time_of_sent[key]
        duration = end_time - start_time
        if isinstance(duration, timedelta):
            flow_durations[i] = duration.total_seconds()
        else:
            # If duration is not a timedelta, convert it to seconds another way
            flow_durations[i] = float(duration)
    
    return flow_rate_received, flow_rate_sent, flow_durations

# Calculate mean Packet length for each flow
def calculate_mean_packet_length(reverse_flow_tracker, packet_length_sent, packet_length_received):
    mean_packet_length = {}
    sent_key = list(packet_length_sent.keys())

    for i in range(len(packet_length_sent.keys())):
        if packet_length_received.get(reverse_flow_tracker[i]):
            mean_packet_length[i] = (sum(packet_length_sent[sent_key[i]]) + sum(packet_length_received[reverse_flow_tracker[i]])) / (len(packet_length_sent[sent_key[i]]) + len(packet_length_received[reverse_flow_tracker[i]]))

        else:
            mean_packet_length[i] = sum(packet_length_sent[sent_key[i]]) / len(packet_length_sent[sent_key[i]])
    
    return mean_packet_length

# Calculate median Packet length for each flow
def calculate_median_packet_length(reverse_flow_tracker, packet_length_sent, packet_length_received):
    median_packet_length = {}
    sent_key = list(packet_length_sent.keys())
    
    for i in range(len(packet_length_sent.keys())):
        if packet_length_received.get(reverse_flow_tracker[i]):
            median_packet_length[i] = np.median(packet_length_sent[sent_key[i]] + packet_length_received[reverse_flow_tracker[i]])

        else:
            median_packet_length[i] = np.median(packet_length_sent[sent_key[i]])

    return median_packet_length

# Calculate mode Packet length for each flow
def calculate_mode_packet_length(reverse_flow_tracker, packet_length_sent, packet_length_received):
    mode_packet_length = {}
    sent_key = list(packet_length_sent.keys())
    
    for i in range(len(packet_length_sent.keys())):
        if packet_length_received.get(reverse_flow_tracker[i]):
            mode_packet_length[i] = mode(packet_length_sent[sent_key[i]] + packet_length_received[reverse_flow_tracker[i]])

        else:
            mode_packet_length[i] = mode(packet_length_sent[sent_key[i]])

    return mode_packet_length

# Calculate variance of Packet length for each flow
def calculate_variance_of_packet(reverse_flow_tracker, packet_length_sent, packet_length_received):
    variance_packet_length = {}
    sent_key = list(packet_length_sent.keys())

    for i in range(len(packet_length_sent.keys())):
        if packet_length_received.get(reverse_flow_tracker[i]):
            variance_packet_length[i] = round(np.var((packet_length_sent[sent_key[i]] + packet_length_received[reverse_flow_tracker[i]]), ddof=1), 6)    

        else:
            variance_packet_length[i] = round(np.var(packet_length_sent[sent_key[i]] , ddof=1), 6)

    return variance_packet_length

# Calculate standard deviation of packet length for each flow
def calculate_std_of_packet(reverse_flow_tracker, packet_length_sent, packet_length_received):
    std_packet_length = {}
    sent_key = list(packet_length_sent.keys())

    for i in range(len(packet_length_sent.keys())):
        if packet_length_received.get(reverse_flow_tracker[i]):
            std_packet_length[i] = round(np.std((packet_length_sent[sent_key[i]] + packet_length_received[reverse_flow_tracker[i]]), ddof=1), 6)

        else:
            std_packet_length[i] = round(np.std(packet_length_sent[sent_key[i]] , ddof=1), 6)
    
    return std_packet_length

# Calculate coefficient of variation of packet length for each flow
def calculate_cfv_of_packet(std_packet_length, mean_packet_length):
    cfv_packet_length = {}

    for i in range(len(std_packet_length.keys())):
        cfv_packet_length[i] = round((std_packet_length[i] / mean_packet_length[i]) * 100, 6)

    return cfv_packet_length

# Calculate skew from median packet length
def calculate_skew_from_median_packet(std_packet_length, mean_packet_length, median_packet_length):
    # Calculate the cfv of packet length for each flow
    skew_median_packet_length = {}

    for i in range(len(mean_packet_length.keys())):
        skew_median_packet_length[i] = round((3 * (mean_packet_length[i] - median_packet_length[i])) / std_packet_length[i], 6)

    return skew_median_packet_length

# Calculate skew from mode packet length
def calculate_skew_from_mode_packet(std_packet_length, mean_packet_length, mode_packet_length):
    skew_mode_packet_length = {}
    
    for i in range(len(mean_packet_length.keys())):
        skew_mode_packet_length[i] = round((mean_packet_length[i] - mode_packet_length[i]) / std_packet_length[i] , 6)
    
    return skew_mode_packet_length

# Calculate mean Packet time for each flow
def calculate_mean_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker):
    mean_times = {}
    mean_seconds = {}
    sent_keys = list(time_stamp_sent_packet.keys())

    for q in range(len(time_stamp_sent_packet.keys())):
        if time_stamp_received_packet.get(reverse_flow_tracker[q]):
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]] + time_stamp_received_packet[reverse_flow_tracker[q]])
        
            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = [datetime_timestamps[i] - datetime_timestamps[i - 1] for i in range(1, len(datetime_timestamps))]

            # Calculate the mean packet time - results iin date-time format
            mean_packet_time = sum(time_diffs, timedelta()) / len(time_diffs)
            mean_times[q] = mean_packet_time
            #print(mean_times)
        
        else:
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = [datetime_timestamps[i] - datetime_timestamps[i - 1] for i in range(1, len(datetime_timestamps))]

            # Calculate the mean packet time - results iin date-time format
            mean_packet_time = sum(time_diffs, timedelta()) / len(time_diffs)
            mean_times[q] = mean_packet_time

        # Converting date-time to seconds
    for flow_count, mean_time in mean_times.items():
        mean_seconds[flow_count] = mean_time.total_seconds()

    return mean_seconds

# Calculate median Packet time for each flow
def calculate_median_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker):
    median_times = {}
    median_seconds = {}
    sent_keys = list(time_stamp_sent_packet.keys())

    for q in range(len(time_stamp_sent_packet.keys())):
        if time_stamp_received_packet.get(reverse_flow_tracker[q]):
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]] + time_stamp_received_packet[reverse_flow_tracker[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]
        
            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)

            # Calculate the median packet time
            median_packet_time = np.median(time_diffs)
            median_times[q] = median_packet_time

        else:
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]
        
            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)

            # Calculate the median packet time
            median_packet_time = np.median(time_diffs)
            median_times[q] = median_packet_time

        # Converting date-time to seconds
    for flow_count, median_time in median_times.items():
        median_seconds[flow_count] = median_time.total_seconds()

    return median_seconds

# Calculate mode Packet time for each flow
def calculate_mode_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker):
    mode_times = {}
    sent_keys = list(time_stamp_sent_packet.keys())

    for q in range(len(time_stamp_sent_packet.keys())):
        if time_stamp_received_packet.get(reverse_flow_tracker[q]):
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]] + time_stamp_received_packet[reverse_flow_tracker[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)
        
            # Convert timedelta objects to total seconds (float)
            time_intervals_seconds = [td.total_seconds() for td in time_diffs]

        else:
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)
        
            # Convert timedelta objects to total seconds (float)
            time_intervals_seconds = [td.total_seconds() for td in time_diffs]            

        # Calculate the mode packet time
        mode_index = int(np.argmax(np.bincount(time_intervals_seconds)))
        mode_times[q] = time_intervals_seconds[mode_index]
        
    return mode_times

# Calculate variance Packet time for each flow
def calculate_variance_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker):
    variance_times = {}
    variance_seconds = {}
    
    sent_keys = list(time_stamp_sent_packet.keys())

    for q in range(len(time_stamp_sent_packet.keys())):
        if time_stamp_received_packet.get(reverse_flow_tracker[q]):
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]] + time_stamp_received_packet[reverse_flow_tracker[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)
        
            # Convert timedelta objects to total seconds (float)
            time_intervals_seconds = [td.total_seconds() for td in time_diffs]
        
        else:
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)
        
            # Convert timedelta objects to total seconds (float)
            time_intervals_seconds = [td.total_seconds() for td in time_diffs]

        # Calculate the variance packet time
        variance_packet_time = np.var(time_intervals_seconds)
        variance_times[q] = round(variance_packet_time, 6)

    return variance_times

# Calculate standard deviation of Packet time for each flow
def calculate_std_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker):
    std_times = {}
    sent_keys = list(time_stamp_sent_packet.keys())

    for q in range(len(time_stamp_sent_packet.keys())):
        if time_stamp_received_packet.get(reverse_flow_tracker[q]):
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]] + time_stamp_received_packet[reverse_flow_tracker[q]])

            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)
        
            # Convert timedelta objects to total seconds (float)
            time_intervals_seconds = [td.total_seconds() for td in time_diffs]

        else:
            sorted_flow = np.sort(time_stamp_sent_packet[sent_keys[q]])
            flow_time = []
            for i in range(len(sorted_flow)):
                flow_time.append(packet_tracker.get(sorted_flow[i]))

            # Explicitly convert timestamp to float
            flow_time = [float(ts) for ts in flow_time]

            # Convert timestamps to datetime objects
            datetime_timestamps = [datetime.utcfromtimestamp(ts) for ts in flow_time]
        
            # Calculate time differences between consecutive packets
            time_diffs = np.diff(datetime_timestamps)
        
            # Convert timedelta objects to total seconds (float)
            time_intervals_seconds = [td.total_seconds() for td in time_diffs]
           
        # Calculate the variance packet time
        std_packet_time = np.std(time_intervals_seconds)
        std_times[q] = round(std_packet_time, 6)

    return std_times

# Calculate coefficient of variation of Packet time for each flow
def calculate_cvt_packet_time(mean_seconds, std_times):
    cvt_times = {}
    #print(mean_seconds)
    #print(std_times)
    
    for i in range(len(mean_seconds.keys())):
        # Calculate the coefficient of variation
        coefficient_of_variation = (std_times[i] / mean_seconds[i]) * 100
        cvt_times[i] = round(coefficient_of_variation, 6)

    return cvt_times

# Calculate skew from median Packet time for each flow
def calculate_skew_median_packet_time(mean_seconds, std_times, median_seconds):
    skew_median_times = {}
    
    for i in range(len(mean_seconds.keys())):
        # Calculate skewness from the median
        skewness_from_median = 3 * (mean_seconds[i] - median_seconds[i]) / std_times[i]
        skew_median_times[i] = round(skewness_from_median, 6)    
    
    return skew_median_times

# Calculate skew from mode Packet time for each flow
def calculate_skew_mode_packet_time(mean_seconds, std_times, mode_times):
    skew_mode_times = {}
    
    for i in range(len(mean_seconds.keys())):
        # Calculate skewness from the median
        skewness_from_mode = (mean_seconds[i] - mode_times[i]) / std_times[i]
        skew_mode_times[i] = round(skewness_from_mode, 6)
    
    return skew_mode_times

def get_tcp_stream(cap):
    stream_index = []
    for packet in cap:
        # Check if it's a TCP packet and extract the TCP stream index
        if 'TCP' in packet and hasattr(packet.tcp, 'stream'):
            stream_index.append(packet.tcp.stream)
    return stream_index

def read_pcapng(file_path):
    packets = rdpcap(file_path)
    return packets

if __name__ == "__main__":
    # Replace 'your_file.pcapng' with the path to your pcapng file
    pcapng_file_path = 'malicious2.pcapng'
    packets = read_pcapng(pcapng_file_path)

    # Create an empty dataframe
    feature_df = pd.DataFrame()

    # For capturing stream index
    cap = pyshark.FileCapture(pcapng_file_path)

    # Get stream index
    stream_index = get_tcp_stream(cap)

    # Extract packet details
    reverse_flow_tracker ,packet_length_sent, packet_length_received, flow_start_time_of_sent, flow_end_time_of_sent, flow_start_time_of_received, flow_end_time_of_received, flow_bytes_sent, flow_bytes_received, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker = extract_flow_bytes_and_time(packets, stream_index)

    # Calculate flow bytes sent and received
    flow_sent, flow_received = calculate_flow_byte(flow_bytes_received, flow_bytes_sent, reverse_flow_tracker)

    #print(flow_sent)
    #print(flow_received)

    

    # Feature 1 : Store flow bytes sent in a dataframe
    feature_df['flow_bytes_sent'] = flow_sent.values()
    
    # Feature 2 : Store flow bytes received in a dataframe
    feature_df['flow_bytes_recv'] = flow_received
    
    # Calculate rate of flow bytes sent
    flow_rate_received, flow_rate_sent, flow_durations = calculate_flow_rate(reverse_flow_tracker, flow_bytes_received, flow_bytes_sent, flow_start_time_of_received, flow_end_time_of_received, flow_start_time_of_sent, flow_end_time_of_sent)
    print("flow_rate_sent:", flow_rate_sent)
    feature_df['flow_duration'] = pd.Series(flow_durations)
    
    # Feature 3 : Rate of flow bytes sent
    feature_df['rt_flow_byte_st'] = flow_rate_sent.values()

    # Feature 4 : Rate of flow bytes received
    feature_df['rt_flow_byte_rc'] = flow_rate_received

    # Calculate mean Packet length for each flow
    mean_packet_length = calculate_mean_packet_length(reverse_flow_tracker, packet_length_sent, packet_length_received)

    # Feature 5 : Mean packet length
    feature_df['mean_pkt_len'] = mean_packet_length.values()

    # Calculate median Packet length for each flow
    median_packet_length = calculate_median_packet_length(reverse_flow_tracker, packet_length_sent, packet_length_received)

    # Feature 6 : Median packet length
    feature_df['median_pkt_len'] = median_packet_length.values()

    # Calculate mode Packet length for each flow
    mode_packet_length = calculate_mode_packet_length(reverse_flow_tracker, packet_length_sent, packet_length_received)

    # Feature 7 : Mode packet length
    feature_df['mode_pkt_len'] = mode_packet_length.values()

    # Calculate variance of Packet length for each flow
    variance_packet_length = calculate_variance_of_packet(reverse_flow_tracker, packet_length_sent, packet_length_received)

    # Feature 8 : Variance of packet length
    feature_df['var_pkt_len'] = variance_packet_length.values()

    std_packet_length = calculate_std_of_packet(reverse_flow_tracker, packet_length_sent, packet_length_received)

    # Feature 9 : Standard deviation of packet length
    feature_df['std_pkt_len'] = std_packet_length.values()

    # Calculate coefficient of variation of Packet length
    cfv_packet_length = calculate_cfv_of_packet(std_packet_length, mean_packet_length)

    # Feature 10 : Coefficient of variation of packet length
    feature_df['cfv_pkt_len'] = cfv_packet_length.values()

    # Calculate skew from median packet length
    skew_median_packet_length = calculate_skew_from_median_packet(std_packet_length, mean_packet_length, median_packet_length)
    
    # Feature 11 : Skew from median packet length
    feature_df['sk_med_pkt_len'] = skew_median_packet_length.values()

    # Calculate skew from mode packet length
    skew_mode_packet_length = calculate_skew_from_mode_packet(std_packet_length, mean_packet_length, mode_packet_length)

    # Feature 12 : Skew from mode packet length
    feature_df['sk_mod_pkt_len'] = skew_mode_packet_length.values()

    # Calculate mean Packet time for each flow
    mean_seconds = calculate_mean_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker)

    # Feature 13 : Mean packet time
    feature_df['mean_pkt_tm'] = mean_seconds.values()

    # Calculate median Packet time for each flow
    median_seconds = calculate_median_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker)

    # Feature 14 : Median packet time
    feature_df['med_pkt_tm'] = median_seconds.values()

    # Calculate mode Packet time for each flow
    mode_times = calculate_mode_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker)
 
    # Feature 15 : Mode packet time
    feature_df['mod_pkt_tm'] = mode_times.values()

    # Calculate variance Packet time for each flow
    variance_times = calculate_variance_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker)

    # Feature 16 : Variance packet time
    feature_df['var_pkt_tm'] = variance_times.values()

    # Calculate standard deviation of Packet time for each flow
    std_times = calculate_std_packet_time(reverse_flow_tracker, time_stamp_sent_packet, time_stamp_received_packet, packet_tracker)

    # Feature 17 : Standard deviation packet time
    feature_df['std_pkt_tm'] = std_times.values()

    # Calculate coefficient of variation of Packet time for each flow
    cvt_times = calculate_cvt_packet_time(mean_seconds, std_times)

    # Feature 18 : Coefficient of variation of packet time
    feature_df['cvt_pkt_tm'] = cvt_times.values()

    # Calculate skew from median Packet time for each flow
    skew_median_times = calculate_skew_median_packet_time(mean_seconds, std_times, median_seconds)

    # Feature 19 : Skew from median packet time
    feature_df['skew_med_pkt_tm'] = skew_median_times.values()

    # Calculate skew from mode Packet time for each flow
    skew_mode_times = calculate_skew_mode_packet_time(mean_seconds, std_times, mode_times)

    # Feature 20 : Skew from mode packet time
    feature_df['skew_mod_pkt_tm'] = skew_mode_times.values()
    
    #feature_df['class'] = [1 for ]
    feature_df.to_csv('maldata.csv')










