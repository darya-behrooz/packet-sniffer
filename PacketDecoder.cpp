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
		std::cout << "Flags: " << +tcpHeader.flags << std::endl;
		std::cout << "Window: " << tcpHeader.window << std::endl;
		std::cout << "Checksum: " << tcpHeader.checksum << std::endl;
		std::cout << "Urgent Pointer: " << tcpHeader.urgPtr << std::endl << std::endl;


		return;
	}
}


int main()
{
	// test packets
	uint8_t ethPacket[] = {0xc8 , 0x96 , 0x5a , 0xdd , 0xbe , 0x60 , 0xbc , 0xfc , 0xe7 , 0x09 , 0xa4 , 0x99 , 0x86 , 0xdd};
	uint8_t ipPacket[] = {0x45 , 0x00 , 0x00 , 0x34 , 0x46 , 0xbc , 0x40 , 0x00 , 0x80 , 0x06 , 0x00 , 0x00 , 0xc0 , 0xa8 , 0x00 , 0x9f , 0x0d , 0x45 , 0xef , 0x44};
	uint8_t tcpPacket[] = {0x2e , 0xe0 , 0x01 , 0xbb , 0x9a , 0x3f , 0xd7 , 0xf2 , 0x46 , 0xc1 , 0x8d , 0x8b , 0x50 , 0x10 , 0x10 , 0x15 , 0xba , 0x98 , 0x00 , 0x00};

	Ethernet::printEthHeader(Ethernet::parseEthHeader(ethPacket));
	IP::printIPheader(IP::parseIPheader(ipPacket));
	TCP::printTCPheader(TCP::parseTCPheader(tcpPacket));


	return 0;
}