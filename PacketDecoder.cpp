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

// prints ip address
std::string printIPaddr(const uint32_t addr)
{
	return std::to_string((addr >> 24) & 0b1111'1111) + "." + std::to_string((addr >> 16) & 0b1111'1111) + "." + std::to_string((addr >> 8) & 0b1111'1111) + "." + std::to_string(addr & 0b1111'1111);
}


namespace Ethernet
{
	// ethernet header format
	struct EthernetHeader
	{
		uint8_t destMAC[6]; // 6 bytes
		uint8_t srcMAC[6]; // 6 bytes
		uint16_t etherType; // 2 bytes
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
	// ip header format
	struct IPheader
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


	// parse ip packet into header
	IPheader parseIPheader(const uint8_t* packet)
	{
		IPheader ipHeader;

		size_t offset = 0;

		uint8_t v_ihl = bite::read8(packet , offset);
		ipHeader.version = v_ihl >> 4;
		ipHeader.headerLength = v_ihl & 0b0000'1111;

		uint8_t typeOfService = bite::read8(packet , offset);
		ipHeader.dscp = typeOfService >> 2;
		ipHeader.ecn = typeOfService & 0b0000'0011;

		ipHeader.totalLength = bite::read16(packet , offset);
		ipHeader.identification = bite::read16(packet , offset);

		uint16_t flagsFragOffset = bite::read16(packet , offset);
		ipHeader.flags = flagsFragOffset >> 13;
		ipHeader.fragmentOffset = flagsFragOffset & 0b0001'1111'1111'1111;

		ipHeader.timeToLive = bite::read8(packet , offset);
		ipHeader.protocol = bite::read8(packet , offset);
		ipHeader.headerChecksum = bite::read16(packet , offset);
		ipHeader.srcAddr = bite::read32(packet , offset);
		ipHeader.destAddr = bite::read32(packet , offset);


		return ipHeader;
	}


	// prints ip header information
	void printIPheader(const IPheader& ipHeader)
	{
		std::cout << "=== IPv4 Packet ===" << std::endl;
		std::cout << "Version: " << +ipHeader.version << std::endl;
		std::cout << "Header Length: " << +ipHeader.headerLength << std::endl;
		std::cout << "Differentiated Services Code Point: " << +ipHeader.dscp << std::endl;
		std::cout << "Explicit congestion notification: " << +ipHeader.ecn << std::endl;
		std::cout << "Total length: " << ipHeader.totalLength << std::endl;
		std::cout << "Identification: " << ipHeader.identification << std::endl;
		std::cout << "Flags: " << +ipHeader.flags << std::endl;
		std::cout << "Fragment offset: " << ipHeader.fragmentOffset << std::endl;
		std::cout << "Time to live: " << +ipHeader.timeToLive << std::endl;
		std::cout << "Protocol: " << +ipHeader.protocol << std::endl;
		std::cout << "Header checksum: " << ipHeader.headerChecksum << std::endl;
		std::cout << "Source IPv4 address: " << printIPaddr(ipHeader.srcAddr) << std::endl;
		std::cout << "Destination IPv4 address: " << printIPaddr(ipHeader.destAddr) << std::endl << std::endl;


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
		uint8_t dataOffset; // 4 bits + 4 0 bits for reserved
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
		std::cout << "Destination port: " << udpHeader.destPort << std::endl;
		std::cout << "Length: " << udpHeader.length << std::endl;
		std::cout << "Checksum: " << udpHeader.checksum << std::endl << std::endl;


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


int main()
{
	// test packets
	uint8_t ethPacket[] = {0xbc , 0xfc , 0xe7 , 0x09 , 0xa4 , 0x99 , 0xc8 , 0x96 , 0x5a , 0xdd , 0xbe , 0x60 , 0x86 , 0xdd};
	uint8_t ipPacket[] = {0x60 , 0x05 , 0x39 , 0x9c , 0x00 , 0x20 , 0x06 , 0x75 , 0x26 , 0x03 , 0x10 , 0x63 , 0x00 , 0x1c , 0x01 , 0x48 , 0x00 , 0x00 , 0x00 , 0x00 , 0x03 , 0x65 , 0x7e , 0xa3 , 0x2a , 0x06 , 0x59 , 0x02 , 0x49 , 0xc1 , 0x3f , 0x00 , 0x18 , 0x05 , 0xf2 , 0x84 , 0x3d , 0x83 , 0x3c , 0xf6};
	uint8_t tcpPacket[] = {0x01 , 0xbb , 0x34 , 0x89 , 0x21 , 0x8d , 0xb2 , 0xa3 , 0x65 , 0xa2 , 0x38 , 0x39 , 0x80 , 0x12 , 0xff , 0xff , 0x7c , 0x24 , 0x00 , 0x00 , 0x02 , 0x04 , 0x05 , 0xa0 , 0x01 , 0x03 , 0x03 , 0x08 , 0x01 , 0x01 , 0x04 , 0x02};
	uint8_t udpPacket[] = {0x01 , 0xbb , 0xf6 , 0x3b , 0x00 , 0x25 , 0xb0 , 0x31};
	uint8_t icmpPacket[] = {0x08 , 0x00 , 0x4d , 0x37 , 0x00 , 0x01 , 0x00 , 0x24};

	Ethernet::printEthHeader(Ethernet::parseEthHeader(ethPacket));
	IP::printIPheader(IP::parseIPheader(ipPacket));
	TCP::printTCPheader(TCP::parseTCPheader(tcpPacket));
	UDP::printUDPheader(UDP::parseUDPheader(udpPacket));
	ICMP::printICMPheader(ICMP::parseICMPheader(icmpPacket));


	return 0;
}
