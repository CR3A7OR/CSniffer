#include <stdlib.h>
#include <stdio.h>
#include <stdint.h> 
#include <pcap.h>
#include <ncurses.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <ctype.h>

// NETWORK INCLUSIONS 
#include <netinet/ip.h> 
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

// (c) 2023 CR3A7OR
// This code is licensed under MIT license (see LICENSE.txt for details)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr)) // returns number of elements in an array

pcap_t* handle; 
int linkLength;
int packets;                          
char *filterdStream;                // Declare filter argument 
char *netInterface;

char** messages;                    // Declare global array of live packets being captured
char** recordList;                  // Declare global array of records within database
char **signatureDetails;            // Declare global array of Snort rule syntax concerning logs
int message_count = 0;              // Declare global number of messages currently stored
int current_line = 0;               // Declare global index of the current top line to display
struct bpf_program *compiled_rules; // Declare global array of compiled BPF expressions
int ruleCount;                      // Declare global number of rules

// Global structure of ncurse windows to be displayed
struct Windows {
   WINDOW *title,*info,*records, *live;
};
struct Windows win;

sqlite3* DB;


/* Function to populate the Title Box */
void poptitleBox(WINDOW *window){
    /* Print contents of vairables to virtual terminal window */
    mvwprintw(window, 1, 1, "Target Interface: %s", netInterface);
    mvwprintw(window, 2, 1, "Filters: %s",filterdStream);
    mvwprintw(window, 2, COLS - 12, "q : quit");
}

/* Function to populate the Info Box */
int popinfoBox(WINDOW *window, char *recordSelect){
    /* Information read from Log presented here */

    /* Clear window and re-draw window box */
    werase(window);
    box(window, 0, 0);

    /* Get dimensions of information window */
    int max_y, max_x;
    getmaxyx(window, max_y, max_x);

    if (recordSelect == ""){
        return 1;
    }

    /* Define variables for storing returned SELECT result of a record */
    sqlite3_stmt *stmt;
    char query[128];
    const unsigned char * title;
    const unsigned char * hash;
    const unsigned char * signature;
    const unsigned char * source;
    const unsigned char * destination;
    const unsigned char * protocol;
    const unsigned char * info;
    int rc;
    char *err_msg = 0;

    /* Compile SELECT query on database where the unique label is equivalent to user selection in record box */
    sprintf(query,"SELECT * FROM PACKETS WHERE LABEL='%s';", recordSelect);
    rc = sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_close(DB);
    }
    /* Execute the previously prepared statement */
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_free(err_msg);
        sqlite3_close(DB);
    }

    /* Populate variable values with respective column values returned */
    hash = sqlite3_column_text(stmt, 1);
    signature = sqlite3_column_text(stmt, 2);
    source = sqlite3_column_text(stmt, 3);
    destination = sqlite3_column_text(stmt, 4);
    protocol = sqlite3_column_text(stmt, 5);
    info = sqlite3_column_text(stmt, 6);
    title = sqlite3_column_text(stmt, 7);

    /* Initialise variables with dynamic memory allocaion using size of retrived values and finalise text contents */
    char *signaturePrint, *sourcePrint, *destinationPrint, *hashPrint;
    signaturePrint = malloc(strlen(signature) + 15);
    sourcePrint = malloc(strlen(source) + 16);
    destinationPrint = malloc(strlen(destination) + 15);
    hashPrint = malloc(strlen(hash) + 7);

    /* Check all pointers have memory allocated correctly */
    if (signaturePrint == NULL || sourcePrint == NULL || destinationPrint == NULL || hashPrint == NULL) {
        printf("Error: Unable to allocate memory.\n");
        return(1);
    }
    /* Copy string titles to be displayed */
    strcpy(signaturePrint, "Signature:    ");
    strcpy(sourcePrint, "Source:       ");
    strcpy(destinationPrint, "Destination:  ");
    strcpy(hashPrint, "Hash: ");

    /* Concatenate values to string titles */
    strcat(signaturePrint, signature);
    strcat(sourcePrint, source);
    strcat(destinationPrint, destination);
    strcat(hashPrint, hash);

    /* Print contents of vairables to virtual terminal window
     * Including: Title, Signature, Source, Destination, Hash
     */
    mvwprintw(window, 1, (max_x / 2  - strlen(title) / 2), title);
    mvwprintw(window, 3, 4, signaturePrint); 
    //mvchgat(7, 4, strlen(signature)-17, A_NORMAL, COLOR_PAIR(1), NULL);
    mvwprintw(window, 4, 4, sourcePrint);
    mvwprintw(window, 5, 4, destinationPrint);  
    mvwprintw(window, max_y - 2, 4, hashPrint); 
    
    /* Generate a internal window design and populate with remaining content retrieved*/
    WINDOW *infoWin = subwin(window, max_y - 8, max_x - 15, 10, 10);
    int max_ysub, max_xsub;
    getmaxyx(infoWin, max_ysub, max_xsub);
    mvwprintw(infoWin, 1, (max_xsub / 2  - strlen("Packet Info") / 2), "Packet Info"); 
    mvwprintw(infoWin,2,3,protocol);
    mvwprintw(infoWin,3,2,info);
    box(infoWin,0,0);

    /* Refresh window's displayed to show new content */
    wrefresh(window);
    touchwin(window);
    wrefresh(infoWin);

    /* Release memory bound to variables */
    free(signaturePrint);
    free(sourcePrint);
    free(destinationPrint);
    free(hashPrint);

    return 1;
}

/* Function to populate the Live Box */
void popliveBox(WINDOW *window, char *packet, bool match){
    /* Live Traffic Printed */

    /* Define a colour pair */
    start_color();
    init_pair(1, COLOR_RED, COLOR_BLACK);

    /* Get dimensions of information window */
    int max_y, max_x;
    getmaxyx(window, max_y, max_x);

    /* Clear window and re-draw window box with initial labels for UI data */
    werase(window);
    box(window, 0, 0);
    mvwprintw(window, 1, 5, "ID    SRC             DST             PROTOCOL    LENGTH    INFO");
    mvwhline(window, 2, 1, ACS_HLINE, COLS - 2);
    
    /* Iteratre over all packets in array and print contents to terminal of the messages */
    for (int i = current_line; i < message_count; i++) {
        if (match){
            //mvwchgat(win.live,i - current_line+3, 5, max_x-2, A_NORMAL, COLOR_PAIR(1), NULL);
            mvwprintw(window,i - current_line+3, 5, messages[i]);  // print stored messages
        }
        else{
            mvwprintw(window,i - current_line+3, 5, messages[i]);  // print stored messages
        }
    }

    /* If space is available updte the packet array by appending packet */
    if (message_count < max_y-4) {
        strcpy(messages[message_count], packet);
        message_count++;
    }
    else {
        /* If the array is full, move all messages up one and append the new message at the bottom */
        for (int i = 0; i < message_count - 1; i++) {
            strcpy(messages[i], messages[i + 1]);
        }
        strcpy(messages[message_count - 1], packet);
    }
    
    /* update current top line index */
    current_line = message_count > max_y ? message_count - max_y : 0;  

    wrefresh(window);
}

/* Call back function for SQL execution storing label records */
int record_count = 0;
static int callback(void* data, int argc, char** argv, char** azColName){
    /* Get dimensions of information window */
    int max_y, max_x;
    getmaxyx(win.records, max_y, max_x);

    /* If the amount of records are less than the window dimensions append record label retrieved to array */
    if (record_count < max_y-4) {
        strcpy(recordList[record_count], argv[0]);
        record_count++;
    }
    return 0;
}

/* Function to Populate the Record Box */
int poprecordBox(WINDOW *window){
    /* SQL database reading */
    
    /* Get dimensions of information window */
    int max_y, max_x;
    getmaxyx(window, max_y, max_x);

    /* Print initial static descriptions covering boxes purpose */
    mvwprintw(window, 1, ((COLS * 1)/3) / 2 - strlen("Records") / 2, "Records");
    mvwhline(window, 2, 1, ACS_HLINE, (COLS * 1)/3 - 3);

    sqlite3_stmt *stmt; // Instance of this object represents a single SQL statement
    int rc;             // Declaration record count variable 
    char *err_msg = 0;  // Initialise variable for storing 
    char query[128];    // Declare SQL query variable

    /* SQL query executed for returning number of records found in PACKETS table */
    strcpy(query,"SELECT count(*) FROM PACKETS;");
    rc = sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_close(DB);
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_free(err_msg);
        sqlite3_close(DB);
    }
    /* Store pointer to number of records */
    int rowcount = sqlite3_column_int(stmt, 0);

    /* De-allocate memory previously allocated to reset list of records*/
    free(recordList);
    record_count = 0;
    /* Dynamically allocate memory at runtime to size of record window for array of pointers used to store retrieved records */
    recordList = (char**) malloc((max_y - 4) * sizeof(char*));
    for (int i = 0; i < max_y-4; i++) {
        recordList[i] = (char*) malloc((max_x + 1) * sizeof(char)); // allocate memory for each message
        recordList[i][0] = '\0'; // initialize each message as an empty string
        //message_count += 1;
    }

    /* SQL query executed to retreive the latest labels column from the Packets table to populate the record window 
     * Retrieved results are past to callback function for passing memory into array of pointers
     */
    sprintf(query,"SELECT LABEL FROM PACKETS LIMIT %d OFFSET %d-%d;",max_y-4 ,rowcount, max_y-4);
    rc = sqlite3_exec(DB, query, callback, 0, &err_msg);  

    /* Error checking to close connection and print error if SQL query fails */
    if (rc != SQLITE_OK ) {
        fprintf(stderr, "Failed to select data\n SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(DB);
        return 1;
    } 
    
    /* Clean the prepared statement from the after prepared queries are evaluated */
    sqlite3_finalize(stmt);

    /* print all labels returned to terminal in a list fashion using incrementing y offset*/
    for (int i = 0; i < max_y-4; i++) {
        mvwprintw(window,i+3, 1, recordList[i]);
    }

    /* Refresh record list to display changes */
    wrefresh(window);

    return 0;
    
}

/* Function for inserting BPF matched packets into the database as a new record */
int sqlInsert(int rule, const struct pcap_pkthdr *packet_header, const u_char *packetptr){
    
    /* Convert packet details into a SHA256 hash */
    unsigned char hashP[64];
    SHA256(packetptr, packet_header->len, hashP);
    char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hash_str[i * 2], "%02x", hashP[i]);
    }

    /* Declared final variables used for storage */
    const char *hash = hash_str; // Initialise hash of packet
    char *sig;                   // Snort Signature
    char source[256];            // Source IP 
    char destination[256];       // Destination IP
    const char *protocol;        // Protocol 
    char info[256];              // Additional packet details + snort rule details
    
    /* Generate unique record log name using current date and time (log-eth-2023-05-10:19:56:04)*/
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    char datetime_str[20]; // YYYY-MM-DD:HH:MM\0
    strftime(datetime_str, sizeof(datetime_str), "%Y-%m-%d:%H:%M:%S", timeinfo);
    char label[29] = "log-eth0-";
    strcat(label,datetime_str);

    /* Structures to cast packet as it is decoded */
    struct ether_header *eth_header; 
    eth_header = (struct ether_header *) packetptr;
    struct ip *iphdr;
    struct icmp* icmphdr;

    /* Cast packet to IP structure to extract source IP, destination IP */
    char packet[256];
    packetptr += linkLength;
    iphdr = (struct ip*)packetptr;
    strcpy(source, inet_ntoa(iphdr->ip_src));
    strcpy(destination, inet_ntoa(iphdr->ip_dst));
    packetptr += 4*iphdr->ip_hl;

    /* Cast packet to ICMP structure to progress pointer accessing ICMP header
     * Retrieve itype,ID,sequence and time to live
     */
    icmphdr = (struct icmp*)packetptr;
    protocol = "ICMP";
    sprintf(packet, "   Echo (ping) %d id=%d seq=%d ttl=%d",icmphdr->icmp_type,ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq),iphdr->ip_ttl);
    
    /* Tokenise rule details previously stored by delimiter of ';' 
     * Iterate through each token appending it to info variable with delimiter of "\n   " creating long string
     */
    char *token = NULL;
    char ruleSnort[1024];
    strcpy(ruleSnort,signatureDetails[rule]);
    ruleSnort[strcspn(ruleSnort, "\n")] = '\0';
    token = strtok(ruleSnort, ";");
    while (token != NULL){
        sig = token;
        token = strtok(NULL, ";");
        sprintf(info,"%s",token);
        token = strtok(NULL, ";");
        sprintf(info,"%s\n   %s",info,token);
        token = strtok(NULL, ";");
        sprintf(info,"%s\n   %s",info,token);
        token = strtok(NULL, ";");
        sprintf(info,"%s\n   %s\n",info,token);
        token = strtok(NULL, ";");
    }

    /* Concatenate packet details formatted to end of Snort rule details  */
    strcat(info,packet);

    sqlite3_stmt *stmt;
    int rc;
    /* SQL query for inseting all prepared variables into relevant column */
    char* query = sqlite3_mprintf("INSERT INTO PACKETS (HASH,SIG,SOURCE,DESTINATION,PROTOCOL,INFO,LABEL) VALUES (?,?,?,?,?,?,?)"); 

    /* Verify SQL query can execute successfully before for execution */
    rc = sqlite3_prepare_v2(DB, query, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(DB));
        sqlite3_close(DB);
        return 1;
    }

    /* Bind parameters to statement parameters */
    sqlite3_bind_text(stmt, 1, hash, 64, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sig, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, source, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, destination, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, protocol, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, info, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, label, -1, SQLITE_STATIC);


    /*  Execute SQL statement inserting into database */
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(DB));
        sqlite3_close(DB);
        return 1;
    }

    /* Clean the prepared statement from the after prepared queries are evaluated */
    sqlite3_finalize(stmt);

    /* Invoke record window function to update diplayed list of available record logs */
    poprecordBox(win.records);
}

/* Function used to perform BPF expression matching against packet to identify as an IOC */
bool patternSearch(const struct pcap_pkthdr *packet_header, const u_char *packetptr){

    /* Iterate over all BPF expressions currently stored in memory */
    for (int i = 0; i < ruleCount; i++) { 
        /* Compare the captured packet against each BPF expression to identify a match 
         * If true forward the packet and pointer of details to insert function
         */
        if (pcap_offline_filter(&compiled_rules[i], packet_header, packetptr) != 0) {
            sqlInsert(i,packet_header,packetptr);
            return true;
        }
    }
    return false;
}

/* Callback function used for each captured packet by socket endpoint */
void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr){
    /* Initialise boolen variable dependent on result of BPF matching againdt packets */
    bool match = patternSearch(packethdr, packetptr);
    /* Structures to cast packet as it is decoded */
    struct ether_header *eth_header;
    struct ether_arp *arphdr;
    struct ip *iphdr;
    struct icmp* icmphdr;
    char srcip[256];                       // Declare Source IP
    char dstip[256];                       // Declare Destination IP
    int caplen = ntohs(packethdr->caplen); // Initialise packet length
    char packet[256];                      // Declare string to be displayed
    char *protocol_name;                   // Declare Protocol

    /* Cast packet as Ethernet frame structure */
    eth_header = (struct ether_header *) packetptr;
    /* Identify the ethernet type using member field between IP and ARP */
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        /*  Skip the datalink layer header and get the IP header fields by moving byte pointer and cast as IP structure */
        packetptr += linkLength;
        iphdr = (struct ip*)packetptr;
        /* Extract the source and destination IP and protocol */
        strcpy(srcip, inet_ntoa(iphdr->ip_src));
        strcpy(dstip, inet_ntoa(iphdr->ip_dst));
        packetptr += 4*iphdr->ip_hl;
        uint16_t protocol = iphdr->ip_p;
        /* Attempt to identify matching IP protocol between ICMP, TCP and UDP */
        switch (protocol) {
            case IPPROTO_ICMP:
                /* Cast packet as ICMP structure and create final output string */
                icmphdr = (struct icmp*)packetptr;
                protocol_name = "ICMP";
                sprintf(packet, "%d    %s  ->  %s    %s    %d    Echo (ping) %d id=%d seq=%d ttl=%d", packets, srcip, dstip, protocol_name, caplen, icmphdr->icmp_type,ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq),iphdr->ip_ttl);
                break;
            case IPPROTO_TCP:
                //tcphdr = (struct tcphdr*)packetptr; 
                protocol_name = "TCP";
                break;
            case IPPROTO_UDP:
                protocol_name = "UDP";
                break;
            default:
                protocol_name = "Unknown";
                break;
        }
        /* Increment packet counter */
        packets += 1;

    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        /* Cast packet as ARP header structure */
        arphdr = (struct ether_arp*)(packetptr + sizeof(struct ether_header)); 
        unsigned char *arpsrc = arphdr->arp_sha;      // Initialise source address of ARP
        unsigned char *arpdst = arphdr->arp_tha;      // Initialise destination address of ARP 
        unsigned char *arp_spa = arphdr->arp_spa;     // Initialise source protocol address 
        unsigned char *arp_tpa = arphdr->arp_tpa;     // Initialise Target protocol address. 
        unsigned short arpOp = ntohs(arphdr->arp_op); // Initialise ARP operation 
        char hex_src[18]; // Declare Source address
        char hex_dst[18]; // Declare Destination address
        protocol_name = "ARP";

        /* Convert ARP MAC addresses into hexadecimal versions */
        for (int i = 0; i < 6; i++) {
            sprintf(hex_src + 3 * i, "%02x:", arpsrc[i]);
        }
        for (int i = 0; i < 6; i++) {
            sprintf(hex_dst + 3 * i, "%02x:", arpdst[i]);
        }

        /* Identify if the ARP packet is a request for who owns and IP or a reply of an IP and create string to display data*/
        if (arpOp == ARPOP_REQUEST) {
            sprintf(packet, "%d %s -> %s %s   %d   Who has %d.%d.%d.%d? Tell %d.%d.%d.%d", packets, hex_src, hex_dst, protocol_name,caplen, arp_tpa[0], arp_tpa[1], arp_tpa[2], arp_tpa[3], arp_spa[0], arp_spa[1], arp_spa[2], arp_spa[3]);
        }
        else if (arpOp == ARPOP_REPLY) {
            sprintf(packet, "%d %s -> %s %s   %d   %s is at %d.%d.%d.%d", packets, hex_src, hex_dst, protocol_name,caplen, hex_src, arp_spa[0], arp_spa[1], arp_spa[2], arp_spa[3]);
        }
        packets += 1;
    
    }
    /* Pass display string and flag to live display function updating terminal */
    popliveBox(win.live, packet,match);
}

/* Function used to breakdown a hexadecimal expression into 4 byte ICMP chunks */
void hex_to_bpf(char* hex_str, char* bpf_expr){
    const char* delim = ":";
    char* saveptr;
    int offset = 4;
    int hex_len = strlen(hex_str);

    /* Pad the hex string with a leading 0 if it has an odd number of characters */
    if (hex_len % 2 == 1){
        char padded_str[hex_len + 1];
        sprintf(padded_str, "0%s", hex_str);
        strcpy(hex_str, padded_str);
        hex_len++;
    }

    /* If the hex string is shorter than 8 characters, add padding on the right */
    while (hex_len < 8){
        char padded_str[hex_len + 2];
        sprintf(padded_str, "%s0", hex_str);
        strcpy(hex_str, padded_str);
        hex_len++;
    }

    /* Split the hex string into chunks of 8 bytes (4 hex digits) and generate a BPF instruction for each chunk */ 
    for (size_t i = 0; i < hex_len; i += 8) {
        char token[9];
        strncpy(token, &hex_str[i], 8);
        uint32_t val = strtol(token, NULL, 16);
        sprintf(bpf_expr + strlen(bpf_expr), " icmp[%d:4] = 0x%x &&", offset, val);
        offset += 4;
    }
    /*  Remove the trailing "&& " from the expression */
    bpf_expr[strlen(bpf_expr)-3] = '\0';
}

/* Function used to create a libpcap socket handle */
pcap_t* create_handler(char* device, char* filter){

    char errbuf[PCAP_ERRBUF_SIZE]; // Declare buffer for any errors
    pcap_t *handle = NULL;         // Declare libpcap socket handle
    pcap_if_t* interfaces = NULL;  // Initialise libpcap interfaces 
    struct bpf_program bpf;        // Declare BPF bytecode  
    bpf_u_int32 netmask;           // Declare netmask
    bpf_u_int32 srcip;             // Declare network  address

    /* If no network interface (device) is specfied or invalid lookup the first applicable interface */
    if (!device || pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
    	if (pcap_findalldevs(&interfaces, errbuf)) {
            fprintf(stderr, "%s\n", errbuf);
            return NULL;
        }
        device = interfaces[0].name;
    }

    /* Validate network device and acquire source IP address and netmask */ 
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }
    /* Assign global pointer to interface address */
    netInterface = device;

    /* Open socket for intercepting live traffic capture */ 
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }
    
    /* Open file stream for reading rules file */
    FILE *reader = fopen("emerging.rules/emerging-icmp.rules", "r");
    int lines = 1;     // Lines read from file stream
    char **filter_exp; // Array of pointer to BPF expressions 

    /* Validate stream successfully opened */
    if(reader != NULL) {
        char snort_rule[1024];    // Store the Snort rule in each line
        char bpf_filter[1024];    // Store the BPF filter 
        char *token;              // Declare pointer to tokenised lines 

        char* temp = NULL;        // Declare temporary token string
        char icode[128];          // Declare ICMP icode
        char itype[128];          // Declare ICMP itype
        char dsize[128];          // Declare ICMP dsize
        char src_value[128] = " and src net "; // Initialise source IP
        char dst_value[128] = " and dst net "; // Initialise destination IP
        char code[10] = "";       // String for final icode format 

        char *token2;             // Declare pointer to tokenised lines 
        char sig_details[1024];   // Declare Snort rule details string
        char* msg_value = NULL;   // Declare Snort msg signature
        char message2[256] = "";  // Declare Snort msg signature
        char* class_value = NULL; // Declare clss type of Snort rule
        char* sid = NULL;         // Declare sid of Snort rule 
        char* rev = NULL;         // Declare rev of Snort rule 
        char* meta = NULL;        // Declare meta data of Snort rule 

        /* Iterate through file stream reading each line and assigning to variable*/
        while(fgets(snort_rule, sizeof(snort_rule), reader)) {
            /* Ignore the first 40 lines and any empty lines with no content */
            if (lines > 40 && (snort_rule[0] != '\r' && snort_rule[0] != '\n' )){
                
                /* Copy relevant prerequisite to string to BPF format  */
                strcpy(bpf_filter, "icmp");
                strcpy(icode, " and icmp[1]");
                strcpy(itype, " and icmp[0] == ");
                strcpy(src_value, " and src net ");
                strcpy(dst_value, " and dst net ");
                strcpy(dsize, " and ip[2:2] ");

                /* Initialise sub string to start tokenisation of Snort rule starting at '('  */
                char *subString = strchr(snort_rule, '(');
                /* If sub string is not empty populate string with duplicate that has null pointer */
                if (subString != NULL) {
                    subString = strdup(subString);
                }
                
                /* Remove newline from end of line and provide null pointer */
                snort_rule[strcspn(snort_rule, "\n")] = '\0';
                token = strtok(snort_rule, " ");
                /* While token is not empty iterate over each word */
                while (token != NULL) {
                    
                    /* Check if token contains word provided */
                    if (strstr(token, "icode:") != NULL) {
                        /* Assign temporary pointer to characters after delimiter ':' */
                        temp = strchr(token, ':') + 1;
                        temp[strlen(temp)-1] = '\0';
                        /* Copy content of icode to variable */
                        strcpy(code,temp);
                        /* Check if the first value is a digit */
                        if (isdigit(temp[0])){
                            /* append comparison operator to front of string*/
                            strcpy(code,"== ");
                            strcat(code, temp);
                        }
                        /* Concatenate code to icode and then to finalised BPF expression */
                        strcat(icode,code);
                        strcat(bpf_filter, icode);
                    }
                    else if (strstr(token, "itype:") != NULL) {
                        temp = strchr(token, ':') + 1;
                        temp[strlen(temp)-1] = '\0';
                        strcat(itype,temp);
                        strcat(bpf_filter, itype);
                    }
                    else if (strstr(token, "$HOME_NET") != NULL) {
                        token = strtok(NULL, " ");
                        strcat(src_value,token);
                        /* Check if source IP contains the any */
                        if (strstr(src_value, "any") == NULL){
                            strcat(bpf_filter, src_value);
                        }
                    }
                    else if (strstr(token, "$EXTERNAL_NET") != NULL) {
                        token = strtok(NULL, " ");
                        strcat(dst_value,token);
                        if (strstr(dst_value, "any") == NULL){
                            strcat(bpf_filter, dst_value);
                        }
                    }
                    else if (strstr(token, "dsize:") != NULL) {
                        temp = strchr(token, ':') + 1;
                        temp[strlen(temp)-1] = '\0';
                        strcat(dsize,temp);
                        strcat(bpf_filter, dsize);

                    }
                    else if (strstr(token, "content:") != NULL) {
                        temp = strchr(token, '"') + 1;
                        temp[strlen(temp)-2] = '\0';
                        /* Conver content into hexadecimal rpresentation */
                        char hex_string[2*strlen(temp)+1];
                        for (int i = 0; i < strlen(temp); i++) {
                            sprintf(&hex_string[i*2], "%02x", temp[i]);
                        }

                        /* Break down hexadecimal representation into 4 byte chunks */
                        char bpf_expr[256] = "";
                        hex_to_bpf(hex_string, bpf_expr);

                        strcat(bpf_filter, " and");
                        strcat(bpf_filter, bpf_expr);

                    }
                    /* Proceed with next token */
                    token = strtok(NULL, " ");
                }

                /* Repeat similar process of extraction for substring but use delimiter of ';' */
                //subString[strcspn(subString, "\n")] = '\0';
                token2 = strtok(subString, ";");
                while (token2 != NULL){    
                    if (strstr(token2, "msg:") != NULL) {
                        msg_value = strchr(token2, '"') + 1;
                        msg_value[strlen(msg_value)-1] = ';';
                        strcpy(message2,msg_value);
                    }
                    else if (strstr(token2, "classtype:") != NULL){
                        class_value = token2;
                        class_value[strlen(class_value)+1] = ';';
                    }
                    else if (strstr(token2, "sid:") != NULL){
                        sid = token2;
                        sid[strlen(sid)+1] = ';';
                    }
                    else if (strstr(token2, "rev:") != NULL){
                        rev = token2;
                        rev[strlen(rev)+1] = ';';
                    }
                    else if (strstr(token2, "metadata:") != NULL){
                        meta = token2;
                        meta[strlen(meta)+1] = ';';
                    }
                    token2 = strtok(NULL, ";");
                }
                /* Release any memory allocated to sub string */
                free(subString);
    
                if (ruleCount == 0){
                    /*  Dynamically allocate memory at runtime to size of character values if first linee */
                    filter_exp = (char **)malloc(sizeof(char *));
                    signatureDetails = (char **)malloc(sizeof(char *));
                }
                else{
                    /* Re-allocate memory dynamically at runtime to allow for more rules to be pointed to */
                    filter_exp = (char **)realloc(filter_exp, sizeof(char *) * ((ruleCount) + 1));
                    signatureDetails = (char **)realloc(signatureDetails, sizeof(char *) * ((ruleCount) + 1));
                }

                /* Dynamically assign memory at runtime for each string stored by using length of final BPF expression */
                filter_exp[ruleCount] = (char *)malloc(sizeof(char) * (strlen(bpf_filter) + 1));
                strcpy(filter_exp[ruleCount], bpf_filter);

                /* Dynamically assign memory at runtime for each string stored by using length of final detail set of Snort rules  */
                sprintf(sig_details, "%s%s;%s;%s;%s",message2,class_value,sid,rev,meta);
                signatureDetails[ruleCount] = (char *)malloc(sizeof(char) * (strlen(sig_details) + 1));
                strcpy(signatureDetails[ruleCount], sig_details);
                ruleCount++;
            }
            /* Increment line counter */
            lines++;
        }
    }
    /* Close fle stream */
    fclose(reader);

    /* Dynamically assign memory at runtime for a array of pointers to each BPF expression stored as byte code */
    compiled_rules = (struct bpf_program*) malloc(sizeof(struct bpf_program) * ruleCount);
    for (int i = 0; i < (ruleCount); i++) {
        /* Compile each BPF string expression into an interpretable byte code */
        if (pcap_compile(handle, &compiled_rules[i], filter_exp[i], 0, netmask) == -1) {
            fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
            return NULL;
        }
    }

    /* Free all memory allocated of pointers to BPF strings */
    for (int i = 0; i < ruleCount; i++) {
        free(filter_exp[i]);
    }
    free(filter_exp);

    /* Convert the packet filter epxression into a packet filter binary */
    if (pcap_compile(handle, &bpf, filter, 1, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    /* Bind the packet filter to the libpcap handle */   
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }
    /* Assign global pointer to filter expression */
    filterdStream = filter;

    return handle;
}

/* Function used for getting link header types and size whilst capturing */
void getLinkHeader(pcap_t* handle){
    int link;
 
    /* Determine the datalink layer type */ 
    if ((link = pcap_datalink(handle)) == PCAP_ERROR) {
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    /* Set the datalink layer header size */ 
    switch (link)
    {
    case DLT_NULL:
        linkLength = 4; //LoopBack Header Size
        break;
 
    case DLT_EN10MB:
        linkLength = 14; //ETH header size
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
        linkLength = 24; // SLIP header size
        break;
 
    default: 
        printf("Unsupported datalink (%d)\n", link);
        linkLength = 0;
    }
}

pthread_t ncurses_thread_id,pcap_thread_id;
/* Function used for safely terminating the program */
void stop_capture(int signo){
    /* End ncurses virtual terminal */
    endwin();
    struct pcap_stat figs;
    /* print to terminal amount of packets captured, received and dropped */
    if (pcap_stats(handle, &figs) >= 0) {
        printf("\n%d packets captured\n", packets);
        printf("%d packets received by filter\n", figs.ps_recv); 
        printf("%d packets dropped\n\n", figs.ps_drop);
    }

    /* Close the packet capture handle and break loop */
    pcap_breakloop(handle);
    pcap_close(handle);

    /* Synchronise threads back into main thread and close the ncurses thread */
    //pthread_join(pcap_thread_id, NULL);
    //pthread_join(ncurses_thread_id, NULL);
    pthread_cancel(ncurses_thread_id);

    /* Close the program */
    exit(0);
}

/*
// Function used for diplaying the time in the title window 
void timePrint(){
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    mvprintw(1, COLS - 21, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
*/

/* Function called by the network thread once created */
void *pcap_thread(void* arg){
    /* Receive packets indefinetly from socket and pass to callback function for analysis */
    struct Windows* win = (struct Windows*)arg;
    pcap_loop(handle, 0, packet_handler, (u_char*)win);

}

/*  Function called by the ncurses thread once created that calls functions to populate virtual terminal */
void *ncurses_thread(void* arg){
    struct Windows* win = (struct Windows*)arg;
    char title[128];
    sprintf(title, "NetSniffer");
    //char tmp[128];
    //sprintf(tmp, "%dx%d", COLS, LINES);
    // Approximate the center
    int x = COLS / 2 - strlen(title) / 2;
    int y = LINES / 2 - 1;
    //mvaddstr(y, x, tmp);

    // TITLE BOX
    box(win->title, 0, 0);
    poptitleBox(win->title);
    wrefresh(win->title);

    // INFORMATION BOX
    box(win->info, 0, 0);
    popinfoBox(win->info,"");
    wrefresh(win->info);

    // RECORD BOX 
    box(win->records, 0, 0);
    poprecordBox(win->records);
    wrefresh(win->records);

    // LIVE BOX
    //struct ip empty_iphdr = {0};
    box(win->live, 0, 0);
    popliveBox(win->live,"",false);
    wrefresh(win->live);
    
    attron(COLOR_PAIR(1));
    mvaddstr(0, x, title);
    attroff(COLOR_PAIR(1));

    refresh();
}

/* Function called to reinitialise variables dependent on terminal size */
void terminalChange(int sig){

    /* Reinitialise the virtual terminal to update data structures */ 
    endwin();
    refresh();
    initscr();
    refresh();
    clear();

    /* reinitialise window sizes to update adaptive display */
    win.title = newwin(4, COLS, 0, 0);
    win.info = newwin((LINES * 3) /5, (COLS * 2)/3, 4, 0);
    win.records = newwin((LINES * 3) /5, (COLS * 1)/3 , 4, (COLS * 2)/3 + 1);
    win.live = newwin((LINES * 2) /5 - 3, COLS, (LINES * 3) /5 + 4, 0);

    /* Return dimensions of live window */
    int max_y, max_x;
    getmaxyx(win.live, max_y, max_x);

    current_line = 0;
    message_count = 0;
    free(messages);
    /*  Dynamically allocate memory at runtime to size of record window for array of pointers used to store retrieved records */
    messages = (char**) malloc((((LINES * 2) /5 - 3) - 4) * sizeof(char*));
    for (int i = 0; i < max_y-4; i++) {
        messages[i] = (char*) malloc((max_x + 1) * sizeof(char)); // allocate memory for each message
        messages[i][0] = '\0'; // initialize each message as an empty string
    }

    /* Refresh the entire virtual terminal and create network thread for active packet capture */
    refresh();
    pthread_create(&ncurses_thread_id, NULL, ncurses_thread, (void*)&win);
    refresh();
    
}

/* Function used for managing user input with  record window */
void listen_for_arrows() {
    int ch; // user input
    int highlight = 0; // Initialise current selection position on record window

    /* Iterate until 'q' key is pressed */
    while ((ch = getch()) != 'q' ) {  
        /* Compre user input against list of available actions*/
        switch (ch) {
            case KEY_UP:
                /* Decrement selection position */
                highlight -= 1;
                /* If selection is less than available set back to 0 */
                if (highlight <= -1){
                    highlight = 0;
                }
                break;
            case KEY_DOWN:
                /* Increment selection position */
                highlight += 1;
                 /* If selection is greater than available set to maximum index */
                if (highlight > ARRAY_SIZE(*recordList)){
                    highlight = ARRAY_SIZE(*recordList);
                }
                break;
            case KEY_LEFT:
                //wprintw(win.records, "Left arrow pressed\n");
                break;
            case KEY_RIGHT:
                //wprintw(win.records, "Right arrow pressed\n");
                break;
            default:
                break;
        }

        /* Populate record box resetting previous highlights*/
        poprecordBox(win.records);
        /* Iterate over each record index */
        for(int i=0; i <= ARRAY_SIZE(*recordList); i++){
            /* If index position is equal to selection */
            if(i == highlight){
                /* Highlight current row selected with attribute */
                wattron(win.records,A_REVERSE);
                mvwprintw(win.records,i+3,1,recordList[i]);
                wattroff(win.records,A_REVERSE);
            }
        }
        
        /* Refresh record list to display changes */
        wrefresh(win.records); 
        
        /* If selected row is not empty then pass record label to information window for population */
        if (*recordList[highlight] != '\0'){
            popinfoBox(win.info,recordList[highlight]);
        }

    }
    /*Clear information box once loop is left and reset records without selection back to default */
    popinfoBox(win.info, "");
    poprecordBox(win.records);
    wrefresh(win.records); 
    wrefresh(win.info); 
    return;
}

/* Main function */
int main(int argc, char *argv[]){
    char *device = NULL, *filter = NULL; // Initialise network interface and filter 
    int opt; 
    filter = 0; // Assign as 0 to indicate by default no filter (allowing all traffic) 

    /* Iterate over all arguments passed and assign relevant pointer options */
    while ((opt = getopt(argc, argv, "i:f:")) != -1){ 
        switch (opt){ 
            case 'i':
                device = strdup(optarg);
                break;
            case 'f':
                filter = strdup(optarg); 
                break;
            default:
                printf("usage: %s [-h] [-i interface] [-f BPF expression]\n", argv[0]);
                exit(0);
                break;
        }
    }

    /* initilaise virtual terminal for ncures */
    initscr();
    noecho();
    cbreak();
    curs_set(0); //Hide Cursor
    keypad(stdscr, TRUE);

    signal(SIGINT, stop_capture);  // User Presses Ctrl + C
    signal(SIGTERM, stop_capture); // User requests to kill program
    signal(SIGQUIT, stop_capture); // Quits but also dumps core

    /* Open database connection */
    char *err_msg = 0;
    int rc = sqlite3_open("packetLogs.db", &DB);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(DB));
        sqlite3_close(DB);
        return 1;
    }
    
    /*Create a libpcap socket  handle */
    handle = create_handler(device, filter);
    if (handle == NULL) {
        return -1;
    }

    /*  Get the type of link layer */
    getLinkHeader(handle);
    if (linkLength == 0) {
        return -1;
    }
    
    /* Populate default empty terminal windows and start ncurses thread */
    terminalChange(1);

    /* Start network capture thread */
    pthread_create(&pcap_thread_id, NULL, pcap_thread, (void*)&win);

    /* Respond to a terminal size change signal by calling function terminalChange*/
    signal(SIGWINCH, terminalChange);

    /* Halt main thread waiting for user input and interate till user presses 'q' */
    while(getch() != 'q'){
        //timePrint();
        listen_for_arrows();
        //timeout(1000);
    }

    /* Call function to safely terminate program */
    stop_capture(0);

    return(0);
}
