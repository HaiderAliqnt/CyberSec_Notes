# Introduction To Networking : HTB Academy
**Made By:** Haider Ali

---


## SECTION 1 : OVERVIEW

A network enables 2 computers to communicate. 
Topologies , mediums and protocols are used to facilitiate it.

To visit a company's website from your home network you have to 
basically exchange data with the company's network since the website is in their network.

We will enter a URL into our browser that will act as an address (Uniform resource locator) for the packets that we intend to send. Also known as Fully Qualified Domain Name (FQDN)

Difference is that FQDN only specifies the address of the website but the URL specifies the packet info and where in the website was it sent to aswell. 

The problem is that we dont know the website's IP so our router sends the packets to the ISP
where the website URl is looked up against the Domain Name Server and the IP is returned. 

Then with that IP the packets are sent over to the intended company network's router which locates the webserver on it's local network and routes the packets towards the webserver.

## SECTION 2 : NETWORK TYPES

A network can be structured differently and can be set up individually hence "types" and "topologies" have been developed to categorize them.

### WAN (Wide Area Network) : 

commonly reffered to as *** THE INTERNET *** 

while dealing with networking tools we have WAN Addr and LAN addr. The WAN addr is generally accessed by the internet.

A WAN is basically a large number of local networks (LAN) connected together.

a large mnc can have an internal WAN aswell.

to identify if the network is WAN look at the routing protocol, it should be WAN specific.

### LAN/WLAN (Local Area Network / Wireless Local Area Network):

a local setup that allows devices present in the local environment to interact with each other without technically using the internet.

IP addresses are assigned to devices for local use. 

A wlan is the same but has wireless capabilities aswell.

### VPN (Virtual Private Network):

allows the user to feel as if they were plugged into a different network.

### 1 -> SITE TO SITE VPN:
both the client and the server are Network devices (router/firewalls) sharing entire network ranges.


### 2 -> REMOTE ACCESS VPN:
involves the client's computer creating a virtual interface that behaves as if it is on a client's network.

### 3 -> SSL VPN:
the common type of vpn that is basically done within our web browser.

## SECTION 3: NETWORK TOPOLOGIES

A network topology is the physical and logical connections of devices in a network. 

The transmission medium layout used to connect devices is the physical topology of the network.

the connection of nodes and the cabling is the logical topology of a network, which dictates how media/data is transmitted across the network.

The entire network topology is divided into 3 areas:

1 -> CONNECTIONS
2 -> NODES - NETWORK INTERFACE CONTROLLER (NICs)
3 -> CLASSIFICATIONS

### CONNECTIONS:

#### - WIRED:
    1 -> coaxial cabling
    2 -> Glass fibre cabling
    3 -> Twisted-pair cabling

#### - WIRELESS:
    1 -> WIFI
    2 -> Cellular
    3 -> Satellite

### NODES:
    Network nodes are the transmission medium's connection points to transmitters and receivers of electrical, optical, or radio signals in the medium
    
    -> REPEATER
    -> HUBS
    -> SATELLITE
    -> BRIDGES
    -> SWITCHES
    -> ROUTER/MODEM
    -> GATEWAYS
    -> FIREWALLS

### CLASSIFICATION:
    We can imagine a topology as a virtual form or structure of a network. This form does not necessarily correspond to the actual physical arrangement of the devices in the network. Therefore these topologies can be either physical or logical.

    -> Point-to-Point	
    -> Bus
    -> Star	
    -> Ring
    -> Mesh	
    -> Tree
    -> Hybrid	
    -> Daisy Chain

#### Point-to-Point:

In this topology, a direct and straightforward physical link exists only between two hosts


#### Bus:

All hosts are connected via a transmission medium in the bus topology. Every host has access to the transmission medium and the signals that are transmitted over it. There is no central network component that controls the processes on it.


#### Star:

The star topology is a network component that maintains a connection to all hosts. Each host is connected to the central network component via a separate link. This is usually a router, a hub, or a switch. These handle the forwarding function for the data packets.


#### Ring:

The physical ring topology is such that each host or node is connected to the ring with two cables:

-One for the incoming signals and
-another for the outgoing ones.

This means that one cable arrives at each host and one cable leaves. The ring topology typically does not require an active network component. The control and access to the transmission medium are regulated by a protocol to which all stations adhere.

#### Mesh:

Many nodes decide about the connections on a physical level and the routing on a logical level in meshed networks. Therefore, meshed structures have no fixed topology. There are two basic structures from the basic concept: the fully meshed and the partially meshed structure.

-Fully Meshed:
    each host is connected to every other host in the network.
-Partially Meshed:
    endpoints are connected by only one connection.

#### Tree:

The tree topology is an extended star topology that more extensive local networks have in this structure. This is especially useful when several topologies are combined. 

#### Hybrid:

Hybrid networks combine two or more topologies so that the resulting network does not present any standard topologies. For example, a tree network can represent a hybrid topology in which star networks are connected via interconnected bus networks. However, a tree network that is linked to another tree network is still topologically a tree network.

#### Daisy Chain:

In the daisy chain topology, multiple hosts are connected by placing a cable from one node to another.

Since this creates a chain of connections, it is also known as a daisy-chain configuration in which multiple hardware components are connected in a series. This type of networking is often found in automation technology (CAN).


## SECTION 4: PROXIES

A proxy is when a device or service sits in the middle of a connection and acts as a mediator. 

Mediator implies that the device in the middle 
can inspect the traffic. 

### IMPORTANT PROXY TYPES:

#### DEDICATED / FORWARD PROXY:

The Forward Proxy, is what most people imagine a proxy to be. A Forward Proxy is when a client makes a request to a computer, and that computer carries out the request.

#### REVERSE PROXY:

Instead of being designed to filter outgoing requests, it filters incoming ones. The most common goal with a Reverse Proxy, is to listen on an address and forward it to a closed-off network.

#### (NON) TRANSPARENT PROXY:

With a transparent proxy, the client doesn't know about its existence. The transparent proxy intercepts the client's communication requests to the Internet and acts as a substitute instance.


If it is a non-transparent proxy, we must be informed about its existence. For this purpose, we and the software we want to use are given a special proxy configuration that ensures that traffic to the Internet is first addressed to the proxy. If this configuration does not exist, we cannot communicate via the proxy. 