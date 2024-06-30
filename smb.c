#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <json-c/json.h>
#define SMB_HEADER_SIZE 64
#define MAX_PACKET_SIZE 65536
#define MAX_FILE_NAME 256
#define MAX_METADATA 1024
typedef struct {
    char file_name[MAX_FILE_NAME];
    int file_size;
    char src_ip[INET_ADDRSTRLEN];
    int src_port;
    char dst_ip[INET_ADDRSTRLEN];
    int dst_port;
} metadata_t;
void parse_smb2_packet(const u_char *packet, metadata_t *metadata) {
    struct ip *ip_hdr = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr->ip_hl * 4);
    inet_ntop(AF_INET, &(ip_hdr->ip_src), metadata->src_ip, INET_ADDRSTRLEN);
    metadata->src_port = ntohs(tcp_hdr->th_sport);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), metadata->dst_ip, INET_ADDRSTRLEN);
    metadata->dst_port = ntohs(tcp_hdr->th_dport);
    const u_char *smb_packet = packet + 14 + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;
    uint16_t smb_command = smb_packet[12];
    const u_char *smb_data = smb_packet + SMB_HEADER_SIZE;
    if (smb_command == 0x09 || smb_command == 0x0A || smb_command == 0x08 || smb_command == 0x10) {
        uint32_t file_offset = *(uint32_t *)(smb_data + 24);
        file_offset = ntohl(file_offset);
        metadata->file_size = *(uint32_t *)(smb_data + 4);
        metadata->file_size = ntohl(metadata->file_size);
        const char *file_name_ptr = (const char *)(smb_data + file_offset);
        strncpy(metadata->file_name, file_name_ptr, MAX_FILE_NAME - 1);
        metadata->file_name[MAX_FILE_NAME - 1] = '\0';
    } else {
        strncpy(metadata->file_name, "unknown", MAX_FILE_NAME - 1);
        metadata->file_size = 0;
    }
}
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    metadata_t metadata;
    json_object *jarray = json_object_new_array();
    // Open the pcap file
    handle = pcap_open_offline("smb.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }
    // Create a folder for extracted files
    system("mkdir -p extracted_files");
    // Iterate through packets
    while ((packet = pcap_next(handle, &header)) != NULL) {
        parse_smb2_packet(packet, &metadata);
        // Extract file data
        char *file_path = (char *)malloc(strlen(metadata.file_name) + 20); // Adjust size as necessary
        snprintf(file_path, strlen(metadata.file_name) + 20, "extracted_files/%s", metadata.file_name);
        FILE *fp = fopen(file_path, "wb");
        if (fp == NULL) {
            fprintf(stderr, "Error opening file %s for writing\n", file_path);
            free(file_path);
            return 1;
        }
        fwrite(packet, 1, header.len, fp);
        fclose(fp);
        free(file_path);
        // Add metadata to JSON array
        json_object *jfile = json_object_new_object();
        json_object_object_add(jfile, "file_name", json_object_new_string(metadata.file_name));
        json_object_object_add(jfile, "file_size", json_object_new_int(metadata.file_size));
        json_object_object_add(jfile, "src_ip", json_object_new_string(metadata.src_ip));
        json_object_object_add(jfile, "src_port", json_object_new_int(metadata.src_port));
        json_object_object_add(jfile, "dst_ip", json_object_new_string(metadata.dst_ip));
        json_object_object_add(jfile, "dst_port", json_object_new_int(metadata.dst_port));
        json_object_array_add(jarray, jfile);
    }
    // Save JSON metadata to file
    char metadata_file_path[MAX_FILE_NAME];
    snprintf(metadata_file_path, MAX_FILE_NAME, "metadata.json");
    FILE *fp = fopen(metadata_file_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file metadata.json for writing\n");
        return 1;
    }
    json_object_to_file_ext(metadata_file_path, jarray, JSON_C_TO_STRING_PRETTY);
    fclose(fp);
    // Cleanup
    pcap_close(handle);
    json_object_put(jarray);
    return 0;
}
