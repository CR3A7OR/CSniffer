<div align="center">
  <h1> │ CSniffer │ </h1>
</div>

<p align="center" width="75%">
    <img width="40%" src="README_Photos/CSnifferLogo.png">
</p>

My Master's level project which is a functional self-contained network tool capable of identifying IOCs using a well established SNORT Egress rule-set that could be deployed on an internal network in a bastion position to perform packet analysis, cross-examining against existing signatures. It is a deployable tool which uses knowledge based detection to determine if egress network packets are malicious without interfering with the performance of the network through passive listening. The tool aims to remove unnecessary bloat information cluttering the interface and focus on providing a digestible set of core details whilst maintaining a intuitive learning curve for users.

| Linux  | Windows |
|--------|---------|
| ![GitHub Workflow Status](https://github.com/CR3A7OR/AutoSleuth/blob/main/README_Photos/Linux%20passing.svg) | ![GitHub Workflow Status](https://github.com/CR3A7OR/AutoSleuth/blob/main/README_Photos/Windows%20passing.svg) |


## »│ Technical Breakdown
#### │ Capturing Traffic:
> - Network traffic is captured
> - 
#### │ Signature Detection:
> - Packets are decoded
> - 
#### │ Storage:
> - SQLite database is used
>

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

### » Install:
> 1. Clone the repository and run the following commands in the directory
> 2. `autoreconf -i`
> 3. `./configure`
> 4. `make`


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
- Promiscuous comparison with BPF filters
- Record Logging of IOC matches
- 

<div align="center">
--- [ 𝗖𝗥𝟯𝗔𝗧𝟬𝗥 ] // Designed By --- 
</div>
