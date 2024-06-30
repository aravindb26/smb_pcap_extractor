# SMB Packet Extractor

This program extracts file attachments and metadata from SMBv2 packets in a pcap file using `libpcap` and `json-c`.

## Requirements

- GCC
- `libpcap` library
- `json-c` library

## Installation

### Install Dependencies

`sudo apt-get install -y build-essential libpcap-dev libjson-c-dev`

### Compile the Program

`gcc -o smb_extractor smb.c -lpcap -ljson-c`


## Usage

1. Ensure `smb.pcap` is in the same directory as the compiled program.
2. Run the program:

`./smb_extractor`

3. Extracted files will be saved in the `extracted_files` directory.
4. Metadata will be saved in `metadata.json`.

This version covers the essential steps for installation, compilation, and usage.
