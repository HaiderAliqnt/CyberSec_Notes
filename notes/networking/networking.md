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
involves the client's computer 
