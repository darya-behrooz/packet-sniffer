#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>


// reads a set amount and returns the bytes
namespace bite // please laugh
{
	// read 8 bits (1 byte)
	uint8_t read8(const uint8_t* data , size_t& offset)
	{
		return static_cast<uint8_t>(data[offset++]);
	}

	// read 16 bits (2 bytes)
	uint16_t read16(const uint8_t* data , size_t& offset)
	{
		return (static_cast<uint16_t>(data[offset++]) << 8) | static_cast<uint16_t>(data[offset++]);
	}

	// read 32 bits (4 bytes)
	uint32_t read32(const uint8_t* data , size_t& offset)
	{
		return (static_cast<uint32_t>(data[offset++]) << 24) | (static_cast<uint32_t>(data[offset++]) << 16) | (static_cast<uint32_t>(data[offset++]) << 8) | static_cast<uint32_t>(data[offset++]);
	}
}


// prints mac address
std::string printMACaddr(const uint8_t mac[6])
{
	std::ostringstream oss;

	for (int byte = 0; byte < 6; byte++)
	{
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[byte]);

		if (byte != 5)
		{
			oss << ":";
		}
	}


	return oss.str();
}

// prints ipv4 address
std::string printIPv4addr(const uint32_t addr)
{
	return std::to_string((addr >> 24) & 0b1111'1111) + "." + std::to_string((addr >> 16) & 0b1111'1111) + "." + std::to_string((addr >> 8) & 0b1111'1111) + "." + std::to_string(addr & 0b1111'1111);
}

// prints ipv6 address
std::string printIPv6addr(const uint8_t addr[16])
{
	std::ostringstream oss;

	for (int byte = 0; byte < 16; byte += 2)
	{
		oss << std::hex << std::setw(4) << std::setfill('0') << ((static_cast<uint16_t>(addr[byte]) << 8) | static_cast<uint16_t>(addr[byte + 1]));

		if (byte != 14)
		{
			oss << ":";
		}
	}


	return oss.str();
}


namespace Ethernet
{
	// ethernet header format
	struct EthernetHeader
	{
		uint8_t destMAC[6]; // 48 bits
		uint8_t srcMAC[6]; // 48 bits
		uint16_t etherType; // 16 bits
	};


	// parse ethernet packet into header
	EthernetHeader parseEthHeader(const uint8_t* packet)
	{
		EthernetHeader ethernetHeader;

		size_t offset = 0;

		for (int byte = 0; byte < 6; byte++)
		{
			ethernetHeader.destMAC[byte] = bite::read8(packet , offset);
		}

		for (int byte = 0; byte < 6; byte++)
		{
			ethernetHeader.srcMAC[byte] = bite::read8(packet , offset);
		}

		ethernetHeader.etherType = bite::read16(packet , offset);


		return ethernetHeader;
	}


	// prints ethernet header information
	void printEthHeader(const EthernetHeader& ethernetHeader)
	{
		std::cout << "=== Ethernet Packet ===" << std::endl;
		std::cout << "Destination Mac Address: " << printMACaddr(ethernetHeader.destMAC) << std::endl;
		std::cout << "Source Mac Address: " << printMACaddr(ethernetHeader.srcMAC) << std::endl;
		std::cout << "EtherType: " << std::hex << ethernetHeader.etherType << std::dec << std::endl << std::endl;


		return;
	}
}


namespace IP
{
	namespace IPv4
	{
		// ipv4 header format
		struct IPv4header
		{
			uint8_t version; // 4 bits 
			uint8_t headerLength; // 4 bits
			uint8_t dscp; // 6 bits
			uint8_t ecn; // 2 bits
			uint16_t totalLength; // 16 bits
			uint16_t identification; // 16 bits
			uint8_t flags; // 3 bits
			uint16_t fragmentOffset; // 13 bits
			uint8_t timeToLive; // 8 bits
			uint8_t protocol; // 8 bits
			uint16_t headerChecksum; // 16 bits
			uint32_t srcAddr; // 32 bits
			uint32_t destAddr; // 32 bits
		};


		// parse ipv4 packet into header
		IPv4header parseIPv4header(const uint8_t* packet)
		{
			IPv4header ipv4Header;

			size_t offset = 0;

			uint8_t v_ihl = bite::read8(packet , offset);
			ipv4Header.version = v_ihl >> 4;
			ipv4Header.headerLength = v_ihl & 0b0000'1111;

			uint8_t typeOfService = bite::read8(packet , offset);
			ipv4Header.dscp = typeOfService >> 2;
			ipv4Header.ecn = typeOfService & 0b0000'0011;

			ipv4Header.totalLength = bite::read16(packet , offset);
			ipv4Header.identification = bite::read16(packet , offset);

			uint16_t flagsFragOffset = bite::read16(packet , offset);
			ipv4Header.flags = flagsFragOffset >> 13;
			ipv4Header.fragmentOffset = flagsFragOffset & 0b0001'1111'1111'1111;

			ipv4Header.timeToLive = bite::read8(packet , offset);
			ipv4Header.protocol = bite::read8(packet , offset);
			ipv4Header.headerChecksum = bite::read16(packet , offset);
			ipv4Header.srcAddr = bite::read32(packet , offset);
			ipv4Header.destAddr = bite::read32(packet , offset);


			return ipv4Header;
		}


		// prints ipv4 header information
		void printIPv4header(const IPv4header& ipv4Header)
		{
			std::cout << "=== IPv4 Packet ===" << std::endl;
			std::cout << "Version: " << +ipv4Header.version << std::endl;
			std::cout << "Header Length: " << +ipv4Header.headerLength << std::endl;
			std::cout << "Differentiated Services Code Point: " << +ipv4Header.dscp << std::endl;
			std::cout << "Explicit congestion Notification: " << +ipv4Header.ecn << std::endl;
			std::cout << "Total Length: " << ipv4Header.totalLength << std::endl;
			std::cout << "Identification: " << ipv4Header.identification << std::endl;
			std::cout << "Flags: " << +ipv4Header.flags << std::endl;
			std::cout << "Fragment Offset: " << ipv4Header.fragmentOffset << std::endl;
			std::cout << "Time To Live: " << +ipv4Header.timeToLive << std::endl;
			std::cout << "Protocol: " << +ipv4Header.protocol << std::endl;
			std::cout << "Header Checksum: " << ipv4Header.headerChecksum << std::endl;
			std::cout << "Source IPv4 Address: " << printIPv4addr(ipv4Header.srcAddr) << std::endl;
			std::cout << "Destination IPv4 Address: " << printIPv4addr(ipv4Header.destAddr) << std::endl << std::endl;


			return;
		}
	}


	namespace IPv6
	{
		// ipv6 header format
		struct IPv6header
		{
			uint8_t version; // 4 bits
			uint8_t trafficClass; // 8 bits
			uint32_t flowLabel; // 20 bits
			uint16_t payloadLength; // 16 bits
			uint8_t nextHeader; // 8 bits
			uint8_t hopLimit; // 8 bits
			uint8_t srcAddr[16]; // 128 bits
			uint8_t destAddr[16]; // 128 bits
		};


		// parse ipv6 packet into header
		IPv6header parseIPv6header(const uint8_t* packet)
		{
			IPv6header ipv6Header;

			size_t offset = 0;

			uint32_t vTcFl = bite::read32(packet , offset);
			ipv6Header.version = vTcFl >> 28;
			ipv6Header.trafficClass = (vTcFl >> 20) & 0b1111'1111;
			ipv6Header.flowLabel = vTcFl & 0b1111'1111'1111'1111'1111;

			ipv6Header.payloadLength = bite::read16(packet , offset);
			ipv6Header.nextHeader = bite::read8(packet , offset);
			ipv6Header.hopLimit = bite::read8(packet , offset);

			for (int byte = 0; byte < 16; byte++)
			{
				ipv6Header.srcAddr[byte] = bite::read8(packet , offset);
			}

			for (int byte = 0; byte < 16; byte++)
			{
				ipv6Header.destAddr[byte] = bite::read8(packet , offset);
			}


			return ipv6Header;
		}


		// prints ipv6 header information
		void printIPv6header(const IPv6header& ipv6Header)
		{
			std::cout << "=== IPv6 Packet ===" << std::endl;
			std::cout << "Version: " << +ipv6Header.version << std::endl;
			std::cout << "Traffic Class: " << +ipv6Header.trafficClass << std::endl;
			std::cout << "Flow Label: " << ipv6Header.flowLabel << std::endl;
			std::cout << "Payload Length: " << ipv6Header.payloadLength << std::endl;
			std::cout << "Next Header: " << +ipv6Header.nextHeader << std::endl;
			std::cout << "Hop Limit: " << +ipv6Header.hopLimit << std::endl;
			std::cout << "Source Address: " << printIPv6addr(ipv6Header.srcAddr) << std::endl;
			std::cout << "Destination Address: " << printIPv6addr(ipv6Header.destAddr) << std::endl << std::endl;
		}
	}
}


namespace ARP
{
	// arp header format
	struct ARPheader
	{
		uint16_t hType; // 16 bits
		uint16_t pType; // 16 bits
		uint8_t hLength; // 8 bits
		uint8_t pLength; // 8 bits
		uint16_t operation; // 16 bits
		uint8_t shAddr[6]; // 48 bits
		uint32_t	spAddr; // 32 bits
		uint8_t thAddr[6]; // 48 bits
		uint32_t tpAddr; // 32 bits
	};


	// parse arp packet into header
	ARPheader parseARPheader(const uint8_t* packet)
	{
		ARPheader arpHeader;

		size_t offset = 0;

		arpHeader.hType = bite::read16(packet , offset);
		arpHeader.pType = bite::read16(packet , offset);
		arpHeader.hLength = bite::read8(packet , offset);
		arpHeader.pLength = bite::read8(packet , offset);
		arpHeader.operation = bite::read16(packet , offset);
		
		for (int byte = 0; byte < 6; byte++)
		{
			arpHeader.shAddr[byte] = bite::read8(packet , offset);
		}

		arpHeader.spAddr = bite::read32(packet , offset);

		for (int byte = 0; byte < 6; byte++)
		{
			arpHeader.thAddr[byte] = bite::read8(packet , offset);
		}

		arpHeader.tpAddr = bite::read32(packet , offset);


		return arpHeader;
	}


	// prints arp header information
	void printARPheader(const ARPheader& arpHeader)
	{
		std::cout << "=== ARP Packet ===" << std::endl;
		std::cout << "Hardware Type: " << arpHeader.hType << std::endl;
		std::cout << "Protocol Type: " << arpHeader.pType << std::endl;
		std::cout << "Hardware Length: " << +arpHeader.hLength << std::endl;
		std::cout << "Protocol Length: " << +arpHeader.pLength << std::endl;
		std::cout << "Operation: " << arpHeader.operation << std::endl;
		std::cout << "Sender Hardware Address: " << printMACaddr(arpHeader.shAddr) << std::endl;
		std::cout << "Sender Protcol Address: " << printIPv4addr(arpHeader.spAddr) << std::endl;
		std::cout << "Target Hardware Address: " << printMACaddr(arpHeader.thAddr) << std::endl;
		std::cout << "Target Protocol Address: " << printIPv4addr(arpHeader.tpAddr) << std::endl << std::endl;


		return;
	}
}


namespace ICMP
{
	// icmp header format
	struct ICMPheader
	{
		uint8_t type; // 8 bits
		uint8_t code; // 8 bits
		uint16_t checksum; // 16 bits
	};


	// parse icmp packet into header
	ICMPheader parseICMPheader(const uint8_t* packet)
	{
		ICMPheader icmpHeader;

		size_t offset = 0;

		icmpHeader.type = bite::read8(packet , offset);
		icmpHeader.code = bite::read8(packet , offset);
		icmpHeader.checksum = bite::read16(packet , offset);


		return icmpHeader;
	}


	// prints icmp header information
	void printICMPheader(const ICMPheader& icmpHeader)
	{
		std::cout << "=== ICMP Packet ===" << std::endl;
		std::cout << "Type: " << +icmpHeader.type << std::endl;
		std::cout << "Code: " << +icmpHeader.code << std::endl;
		std::cout << "Checksum: " << icmpHeader.checksum << std::endl << std::endl;


		return;
	}
}


namespace TCP
{
	// tcp header format
	struct TCPheader
	{
		uint16_t srcPort; // 16 bits
		uint16_t destPort; // 16 bits
		uint32_t seqNum; // 32 bits
		uint32_t ackNum; // 32 bits
		uint8_t dataOffset; // 4 bits
		uint8_t reserved = 0; // 4 bits set to 0
		uint8_t flags; // 8 bits
		uint16_t window; // 16 bits
		uint16_t checksum; // 16 bits
		uint16_t urgPtr; // 16 bits
	};


	// tcp header flags
	enum struct TCPflags : uint8_t
	{
		CWR = 1 << 7, // congestion window reduced
		ECE = 1 << 6, // ecn-echo
		URG = 1 << 5, // urgent pointer field is significant
		ACK = 1 << 4, // acknowledgement field is significant
		PSH = 1 << 3, // push function
		RST = 1 << 2, // reset the connection
		SYN = 1 << 1, // synchronise sequence numbers
		FIN = 1 << 0  // last packet no more data
	};


	// check flags
	inline constexpr bool operator&(uint8_t lhs , TCPflags rhs)
	{
		return lhs & static_cast<uint8_t>(rhs);
	}


	void parseTCPflags(const uint8_t& flags)
	{
		std::cout << "Flags: ";

		if (flags & TCPflags::CWR) std::cout << "CWR ";
		if (flags & TCPflags::ECE) std::cout << "ECE ";
		if (flags & TCPflags::URG) std::cout << "URG ";
		if (flags & TCPflags::ACK) std::cout << "ACK ";
		if (flags & TCPflags::PSH) std::cout << "PSH ";
		if (flags & TCPflags::RST) std::cout << "RST ";
		if (flags & TCPflags::SYN) std::cout << "SYN ";
		if (flags & TCPflags::FIN) std::cout << "FIN";
		std::cout << std::endl;


		return;
	}


	// parse tcp packet into header
	TCPheader parseTCPheader(const uint8_t* packet)
	{
		TCPheader tcpHeader;

		size_t offset = 0;

		tcpHeader.srcPort = bite::read16(packet , offset);
		tcpHeader.destPort = bite::read16(packet , offset);
		tcpHeader.seqNum = bite::read32(packet , offset);
		tcpHeader.ackNum = bite::read32(packet , offset);
		tcpHeader.dataOffset = bite::read8(packet , offset) >> 4;
		tcpHeader.flags = bite::read8(packet , offset);
		tcpHeader.window = bite::read16(packet , offset);
		tcpHeader.checksum = bite::read16(packet , offset);
		tcpHeader.urgPtr = bite::read16(packet , offset);


		return tcpHeader;
	}


	// prints tcp header information
	void printTCPheader(const TCPheader& tcpHeader)
	{
		std::cout << "=== TCP Packet ===" << std::endl;
		std::cout << "Source Port: " << tcpHeader.srcPort << std::endl;
		std::cout << "Destination Port: " << tcpHeader.destPort << std::endl;
		std::cout << "Sequence Number: " << tcpHeader.seqNum << std::endl;
		std::cout << "Acknowledgement Number: " << tcpHeader.ackNum << std::endl;
		std::cout << "Data Offset: " << +tcpHeader.dataOffset << std::endl;
		std::cout << "Reserved: " << +tcpHeader.reserved << std::endl;
		parseTCPflags(tcpHeader.flags);
		std::cout << "Window: " << tcpHeader.window << std::endl;
		std::cout << "Checksum: " << tcpHeader.checksum << std::endl;
		std::cout << "Urgent Pointer: " << tcpHeader.urgPtr << std::endl << std::endl;


		return;
	}
}


namespace UDP
{
	// udp header format
	struct UDPheader
	{
		uint16_t srcPort; // 16 bits
		uint16_t destPort; // 16 bits
		uint16_t length; // 16 bits
		uint16_t checksum; // 16 bits
	};


	// parse udp packet into header
	UDPheader parseUDPheader(const uint8_t* packet)
	{
		UDPheader udpHeader;

		size_t offset = 0;

		udpHeader.srcPort = bite::read16(packet , offset);
		udpHeader.destPort = bite::read16(packet , offset);
		udpHeader.length = bite::read16(packet , offset);
		udpHeader.checksum = bite::read16(packet , offset);


		return udpHeader;
	}


	// prints udp header information
	void printUDPheader(const UDPheader& udpHeader)
	{
		std::cout << "=== UDP Packet ===" << std::endl;
		std::cout << "Source Port: " << udpHeader.srcPort << std::endl;
		std::cout << "Destination Port: " << udpHeader.destPort << std::endl;
		std::cout << "Length: " << udpHeader.length << std::endl;
		std::cout << "Checksum: " << udpHeader.checksum << std::endl << std::endl;


		return;
	}
}


int main()
{
	// static test packets go here!
	uint8_t ethPacket[] = {};
	uint8_t ipv4Packet[] = {};
	uint8_t ipv6Packet[] = {};
	uint8_t arpPacket[] = {};
	uint8_t tcpPacket[] = {};
	uint8_t udpPacket[] = {};
	uint8_t icmpPacket[] = {};

	Ethernet::printEthHeader(Ethernet::parseEthHeader(ethPacket));
	IP::IPv4::printIPv4header(IP::IPv4::parseIPv4header(ipv4Packet));
	IP::IPv6::printIPv6header(IP::IPv6::parseIPv6header(ipv6Packet));
	ARP::printARPheader(ARP::parseARPheader(arpPacket));
	ICMP::printICMPheader(ICMP::parseICMPheader(icmpPacket));
	TCP::printTCPheader(TCP::parseTCPheader(tcpPacket));
	UDP::printUDPheader(UDP::parseUDPheader(udpPacket));


	return 0;
}
