# Introduction To Networking : HTB Academy
**Made By:** Haider Ali

---
# SECTION 10 -  TILL

## SECTION 10 : SUBNETTING

The division of an address range of IPv4 addresses into several smaller address ranges is called subnetting.

Let us take the following IPv4 address and subnet mask as an example:

IPv4 Address: 192.168.12.160
Subnet Mask: 255.255.255.192
CIDR: 192.168.12.160/26


first convert the subnet mask into binary 
so 255.255.255.192 goes to 
11111111.11111111.11111111.11000000 
here all the 1 bits are network bits 
and all the 0 bits are host bits

network part : 11111111.11111111.11111111.11
host part : 000000 

from the host part we can discover how many devices we can connect on the network through the formula (2^n - 2) where n is the number of 0s.

the 2 connections we subtracted are to account for the first and last IP which are network address and and broadcast address respectively.

The network address is vital for the delivery of a data packet. If the network address is the same for the source and destination address, the data packet is delivered within the same subnet.


So if we now set all bits to 0 in the host part of the IPv4 address, we get the respective subnet's network address.

If we set all bits in the host part of the IPv4 address to 1, we get the broadcast address.

Since we now know that the IPv4 addresses 192.168.12.128(netw addr) and 
192.168.12.191 (broadcast addr) are assigned, all other IPv4 addresses are accordingly between 192.168.12.129-190.

### HOW TO EXTEND A SUBNET:

If more devices are to be added into a subnet and hence more IPs are needed then the network can be expanded. 

1 -> Decide how many more hosts are going to be added 

2 -> Compare them with powers of 2

example : lets suppose I want to add atleast 17 more hosts then 

powers of 2: 
256 128 62 32 16 8 4 2 

then ofcourse i would need to go till 32 to get atleast 17 
32 is 2 ^ 5 
that means i need to take 5 bits from the network portion and add them to the host portion 

so from 11111111.11111111.11111111.11000000 
it becomes 11111111.11111111.11111000.00000000

5 bits removed from network part and then added to the host part and hence network expanded.

### HOW TO DIVIDE INTO SMALLER SUBNETS:

add the number of bits required by dividing the ammount of subnets to be created by 2.

then look at the possible number of IPs they can form.


## SECTION 11:MAC ADDRESSES:

Each host in a network has its own 48-bit (6 octets) Media Access Control (MAC) address, represented in hexadecimal format. MAC is the physical address for our network interfaces. There are several different standards for the MAC address:

-> Ethernet (IEEE 802.3)
-> Bluetooth (IEEE 802.15)
-> WLAN (IEEE 802.11)

Each network card has its individual MAC address, which is configured once on the manufacturer's hardware side but can always be changed, at least temporarily.

