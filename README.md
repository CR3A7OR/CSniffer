<div align="center">
  <h1> │ CSniffer │ </h1>
</div>

<p align="center" width="75%">
    <img width="40%" src="README_Photos/CSnifferLogo.png">
</p>

My Master's level project which is a functional self-contained network tool capable of identifying IOCs using a well established SNORT Egress rule-set that could be deployed on an internal network in a bastion position to perform packet analysis, cross-examining against existing signatures. It is a deployable tool which uses knowledge based detection to determine if egress network packets are malicious without interfering with the performance of the network through passive listening. The tool aims to remove unnecessary bloat information cluttering the interface and focus on providing a digestible set of core details whilst maintaining a intuitive learning curve for users.

| Linux  | Windows |
|--------|---------|
| ![GitHub Workflow Status](https://github.com/CR3A7OR/AutoSleuth/blob/main/README_Photos/Linux%20passing.svg) | ![GitHub Workflow Status](https://img.shields.io/badge/Windows-failed-red) |


## »│ Technical Breakdown
#### │ Capturing Traffic:
> - Network traffic is captured using the C `libpcap` which create a packet capture endpoint to receive traffic on, if successful the function returns a libpcap socket handle which relies on the use of a Linux PF_PACKET where the capture mechanism uses an internal ring buffer to write the packet to kernel memory with direct memory access
> - A PF_PACKET socket clones the structure and skips the upper layer handling of the TCP/IP stack allowing for the capture of raw Ethernet frames being passed into applications via the socket interface
> - A packet header and content, are passed, and a character pointer is set to the beginning of the packet buffer which is then advanced to a particular protocol header by the size in bytes to allow for protocol distinguishment. The header is then mapped to a relevant header structure by casting the character pointer to a protocol specific structure, in this instance (ICMP or ARP)
#### │ Signature Detection:
> - The program will first convert each Snort rule into a `BPF filter` format, using the pcap compile function the for loop compiles each filter expression into a BPF rule and stores it within memory
> - Decoding each packet is a hard coded but systematic process of elimentation based on the contents of the packet, it takes advantage of a collection of preprocessor macros and type declarations, serving as the header or interface documentation for various network programming interfaces 
> - BPF filter expression is compiled and applied to a packet, it is executed using a kernel level virtual machine (VM) which iterates through a series of instructions, pushing and popping values from the stack as needed and then returns a non-zero value if the packet matches the filter, and zero if it does not. The eval algorithm simulates a generalised coverage of the acyclic control flow graph *(arp.src=XXX)*
#### │ Storage:
> - `SQLite3` database is used for the project to record and store any IOC packets identified as a match with a BPF expression.  
> - Packet information has been extracted and is done with a function that binds string values to placeholders in SQLite prepared statements for one final transaction. Inserting into the database is done once all packet information has been recovered from the packet; a collaboration of SQL queries avoids deadlocks but maintains steady control of order as to perform simultaneous data presentation
> - Retrieval of information is a simple template function that proceeds with an SQL statement selecting all columns from the table where the Label columns match the current record in the window. Population of the information box is invoked by the record window once a arrow key has been pressed, the label at the current record list index is passed for the search query. 


```diff
- THE PROJECT'S CURRENTLY LIMITED TO ARP AND ICMP DECODING, CONTRIBUTIONS TO DECODING WOULD BE APPRECIATED -
```

## »│ Setup

### » Hardware:
Setup a listening device in a `bastion position` on a home network which is capable of intercepting traffic or use `port mirroring` with a switch to ascertain a copy of the network traffic flowing through.  

### » Software:
```
For successful operation the following files/folders are required:
- CSniff.c (converted to executable)
- packetLogs.db
- emerging.rules
```
```
The following system and software are required:
- a POSIX shell
- standard C compiler (c89 or later)
- packet socket option enabled
- autoconf
- Libraries (libpcap-dev / ncurses-dev / libsqlite3-dev / openssl-dev)
```

| Terminal Emulator  | Tested |
|--------|---------|
| Konsole | ✔️ Passing |
| GNU | ✔️ Passing  |
| Alacrity | ✔️ Passing *(transparency effect problem)* |
| XFCE | ✔️ Passing *(transparency effect problem)*  |
| Windows Console *(WSL)* | ✔️ Passing |


### » Install:
> 1. Clone the repository and run the following commands in the directory
> 2. `autoreconf -i`
> 3. `./configure`
> 4. `make`

GNU Compiler:
> gcc -o NetSniffer -g CSniffv3.c -lncurses -lpcap -pthread -lsqlite3 -lssl -lcrypto 


## »│ Operartion
```
sudo ./NetSniffer [optional flags 
    -i [network interface (from ifconfig)] 
    -f [BPF filter] 
  ]
```
**Arrow keys** to move up and down across the records and use **q** to quit

### » Features:
- Live packet viewing *(similar to Wiresharks)*
- Promiscuous pattern matching with BPF filters
- Record Logging of IOC matches
- Filtering of traffic capture by network interface and BPF expression
- Responsive TUI to size changes
- Easily scalable Snort rule-sets 

![Demo CountPages alpha](README_Photos/showcase.gif)

<div align="center">
--- [ 𝗖𝗥𝟯𝗔𝗧𝟬𝗥 ] // Designed By --- 
</div>
