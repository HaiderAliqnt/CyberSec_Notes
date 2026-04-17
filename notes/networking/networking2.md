# Introduction To Networking : HTB Academy
**Made By:** Haider Ali

---
# SECTION 5 -  TILL 10 

## SECTION 5-8: NETWORKING MODELS

Two networking models describe the communication and transfer of data from one host to another, called ISO/OSI model and the TCP/IP model.

### OSI Model:

uses 7 different layers. Layers represent phases in the establishment of each connection through which the sent packets pass.

7 -> APPLICATION : controls input output of data and provides application functions

6 -> PRESENTATION: transfers's system dependent presentation of data into a form that is independent of the system

5 -> SESSION: controls logical connection between 2 systems.

4 -> TRANSPORT: used for end to end control of data transfer detecting and avoiding congestions.

3 -> NETWORK: used to encapsulate the frames into packets and then route those packets by assigning IP addresses, chooses the most efficient path through all possible connections aswell. 

2 -> DATA: this layer enables reliable and error free transmission by dividing the bit stream into frames.

1 -> PHYSICAL: this is the actual physical connection between devices through wires, electric/optical signals are used to transmit data streams over it.

### TCP/IP Model:

uses 4 layers, by merging OSI layers under one name. 


4 -> APPLICATION : allows applications to transfer/recieve data over the network.

3 -> TRANSPORT : decides whether to send data to application using TCP or UDP protocol. 

2 -> INTERNET : responsible for packaging , routing , and IP address assiging.

1 -> LINK : responsible for transferring data over the physically and locally connected devices over a wire using signals in form of bitstreams.

## SECTION 9 : IP/MAC ADDRESSES:

Imagine the network is a city/town ...the IP address would be your home address that tells an observer where you are located in the city/town and the MAC would be your CNIC.

when a device connects to the network it is assigned an IP. This ensures correct data transfer.

### IPV4 :
The most common method of assigning IP addresses is IPv4, which consists of a 32-bit binary number combined into 4 bytes consisting of 8-bit groups (octets) ranging from 0-255.

Binary:	0111 1111.0000 0000.0000 0000.0000 0001
Decimal: 127.0.0.

This format allows 4,294,967,296 unique addresses.

Every device on the network is assigned a unique IP.

IP is divided into 2 parts : host , network

IP blocks were also divided into classes A-E 

### SUBNET MASK :
A subnet mask is a 32-bit binary number that acts as a filter to separate an IP address into its network portion and host portion, allowing devices to determine if a destination is local or requires routing through a gateway.

### CIDR NOTATION:
CIDR notation (Classless Inter-Domain Routing) is a compact way to represent an IP address and its associated network prefix length using a slash (/) followed by a number. 

Example: 192.168.1.0/24 means the first 24 bits define the network, leaving 8 bits for 254 usable host addresses.

### BROADCAST ADDRESS:

used to connect all devices in a network with each other. Sends a message to all devices and in doing so communicates it's IP that the recievers can use to communicate with it.


