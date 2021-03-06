#pragma once
#define MAGIC_PORT 22345 // receiver listens on this port
#define IP_HDR_SIZE 20 /* RFC 791 */
#define ICMP_HDR_SIZE 8 /* RFC 792 */
/* max payload size of an ICMP message originated in the program */
#define MAX_SIZE 65200
/* max size of an IP datagram */
#define MAX_ICMP_SIZE (MAX_SIZE + ICMP_HDR_SIZE)
/* the returned ICMP message will most likely include only 8 bytes
* of the original message plus the IP header (as per RFC 792); however,
* longer replies (e.g., 68 bytes) are possible */
#define MAX_REPLY_SIZE (IP_HDR_SIZE + ICMP_HDR_SIZE + MAX_ICMP_SIZE)
/* ICMP packet types */
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRED 11
#define ICMP_ECHO_REQUEST 8

#define MAX_HOPS 30
#define DEFAULT_TIMEOUT 500


/* remember the current packing state */
#pragma pack (push)
#pragma pack (1)
/* define the IP header (20 bytes) */
class IPHeader {
public:
	u_char h_len : 4; /* lower 4 bits: length of the header in dwords */
	u_char version : 4; /* upper 4 bits: version of IP, i.e., 4 */
	u_char tos; /* type of service (TOS), ignore */
	u_short len; /* length of packet */
	u_short ident; /* unique identifier */
	u_short flags; /* flags together with fragment offset - 16 bits */
	u_char ttl; /* time to live */
	u_char proto; /* protocol number (6=TCP, 17=UDP, etc.) */
	u_short checksum; /* IP header checksum */
	u_long source_ip;
	u_long dest_ip;
};
/* define the ICMP header (8 bytes) */
class ICMPHeader {
public:
	u_char type; /* ICMP packet type */
	u_char code; /* type subcode */
	u_short checksum; /* checksum of the ICMP */
	u_short id; /* application-specific ID */
	u_short seq; /* application-specific sequence */
};
class HopInfo {
public:
	IPHeader *router_ip_hdr;
	ICMPHeader *router_icmp_hdr;
	IPHeader *orig_ip_hdr;
	ICMPHeader *orig_icmp_hdr;
	double RTO; //in ms
	double sent_time; //in ms
	double recvd_time; //in ms
	int probes_sent;
	u_long ip;
	bool is_it_destination;
	bool is_errors;
	u_char error_type;
	u_char error_code;
};
/* now restore the previous packing state */
#pragma pack (pop)
class Parameters {
public:
	HANDLE mutex;
	char* ip;
	std::string host;
	u_long sourceip = 0;
	bool done;
};
class Traceroute {
public:
	Traceroute(char * dest);
	~Traceroute();
	void CreateSocket();
	void LookupHost(char* destinationHost);
	u_short ip_checksum(u_short *buffer, int size);
	void SendFirstSetofProbes();
	double SetDynamicRTO(int index);
	void RetxPackets();
	int SendAndRecv(int count, bool first, bool onlySend, bool onlyReceive);
	void PrintFinalResult();
	void StartReceiving();
	char* LookupDNS(u_long ip);
	//void ReceivePacketLoop();
	void StartDNSThreads();
	SOCKET sock;
	struct sockaddr_in local;
	// structure for connecting to server
	struct sockaddr_in server;
	// structure used in DNS lookups
	struct hostent *remote;
	char* destName;
	HopInfo hop_info[MAX_HOPS];
	HANDLE handles[MAX_HOPS];
	Parameters* dns_params[MAX_HOPS];
};