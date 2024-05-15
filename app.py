from flask import Flask, request, jsonify, send_file
import subprocess
import os
import time

app = Flask(__name__)

capture_dir = os.path.join('captures')

# Dictionary to store packet capture statuses
capture_statuses = {}

def get_capture_filename(capture_id):
    return os.path.abspath(f"{capture_dir}/capture_{capture_id}.pcap")

def get_capture_txt_filename(capture_id):
    return os.path.abspath(f"{capture_dir}/capture_{capture_id}.txt")

@app.route('/start_capture', methods=['POST'])
def start_capture():
    ip_address = request.form.get('ip_address')
    duration = request.form.get('duration')
    network_interface = request.form.get('network_interface')

    # Generate unique ID for the packet capture request
    capture_id = str(int(time.time()))

    # Directory to store capture files
    os.makedirs(capture_dir, exist_ok=True)

    # Run tshark command to start packet capture and save to pcap file
    pcap_filename = get_capture_filename(capture_id)
    tshark_cmd = f"tshark -i {network_interface} -a duration:{duration} -w {pcap_filename}"
    print("Tshark command:", tshark_cmd)  # Debug print
    process = subprocess.Popen(tshark_cmd, shell=True, stderr=subprocess.PIPE)

    try:
        # Sleep for 2 seconds to allow the process to start
        if os.path.exists(pcap_filename) or process.pid:
            status = 'started'
        else:
            status = 'failed'
    except Exception as e:
        status = 'error'
        return jsonify({'error': f'An error occurred: {str(e)}'})

    # Store capture status and process ID
    capture_statuses[capture_id] = {'status': status, 'process_id': process.pid, 'pcap_filename': pcap_filename}

    if status == 'started':
        return jsonify({'message': 'Packet capture started', 'capture_id': capture_id, 'status': status})
    elif status == 'failed':
        return jsonify({'error': 'Failed to start packet capture'})
    else:
        return jsonify({'error': 'An error occurred while starting the packet capture'})

@app.route('/check_status/<capture_id>', methods=['GET'])
def check_status(capture_id):

    print(f"Get Status Request is received with capture id = {capture_id}")

    # Get the pcap filename associated with the capture ID
    pcap_filename = get_capture_filename(capture_id)

    # Check the existance of pcap_filename
    if not os.path.exists(pcap_filename):
        return jsonify({'error': 'Pcap file not found'})

    # Check if a tshark process is running with filename = pcap_filename
    grepstr = f"tshark.*{capture_id}.pcap"
    result = subprocess.run(["pgrep", "-f", grepstr])

    if result.returncode == 0:
        status = "Running"
        tshark_stats_cmd = f"tshark -r {pcap_filename} -T fields -e frame.number"
        tshark_stats_output = subprocess.run(tshark_stats_cmd, shell=True, capture_output=True, text=True)
        packet_count = len(tshark_stats_output.stdout.splitlines()) 
        print("process is running")
    else:
        status = "Completed"
        tshark_stats_cmd = f"tshark -r {pcap_filename} -T fields -e frame.number"
        tshark_stats_output = subprocess.run(tshark_stats_cmd, shell=True, capture_output=True, text=True)
        packet_count = len(tshark_stats_output.stdout.splitlines())
        print("process is not running.")

    return jsonify({'status': status, 'packet_count': packet_count})

@app.route('/open_capture/<capture_id>', methods=['GET'])
def open_capture(capture_id):
    # Get the pcap filename associated with the capture ID
    pcap_filename = get_capture_filename(capture_id)
    txt_filename = get_capture_txt_filename(capture_id)

    # Check if the pcap file exists
    if not os.path.exists(pcap_filename):
        return jsonify({'error': 'Pcap file not found'})

    # Check if the capture has completed
    status_response = check_status(capture_id)
    if status_response.json['status'] != 'Completed':
        return jsonify({'error': 'Capture is not completed yet'})

    # Convert pcap to txt
    tshark_cmd = f"tshark -r {pcap_filename} -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E header=y -E separator=, -E quote=d -E occurrence=f > {txt_filename}"
    subprocess.run(tshark_cmd, shell=True)

    # Send the txt file for download
    return send_file(txt_filename, as_attachment=True)    

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
