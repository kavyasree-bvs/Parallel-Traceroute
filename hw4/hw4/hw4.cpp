// hw4.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

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
/* now restore the previous packing state */
#pragma pack (pop)
/*
* ======================================================================
* ip_checksum: compute Internet checksums
*
* Returns the checksum. No errors possible.
*
* ======================================================================
*/
u_short ip_checksum(u_short *buffer, int size)
{
	u_long cksum = 0;
	/* sum all the words together, adding the final byte if size is odd */
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}
	if (size)
		cksum += *(u_char *)buffer;
	/* add carry bits to lower u_short word */
	cksum = (cksum >> 16) + (cksum & 0xffff);
	/* return a bitwise complement of the resulting mishmash */
	return (u_short)(~cksum);
}
/*
DWORD WINAPI TraceThread(LPVOID params)
{
	...
		do {
			// grab from a producer-consumer queue
			ip = GetNextIP();
			if (ping(ip) == SUCCESS) // ping the IP with TTL 30
			{
				// traceroute to ip using TTL [1, 2, …, 30]; record statistics
				if (successful traceroute)
					InterlockedIncrement(&success);
			}
		} while (success < 10K);
}*/
int main(int argc, char** argv)
{
	//printf("argc %d\n", argc);
	if (argc != 2)
	{
		printf("incorrect number of arguments\n");
		return 0;
	}
	char* destinationHost = argv[1];
	//printf("dest host is %s\n", destinationHost);

	WSADATA wsaData;
	WORD wVersionRequested;
	//Initialize WinSock; once per program run
	wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) 
	{
		printf("WSAStartup error %d\n", WSAGetLastError());
		exit(0);
	}

	/* ready to create a socket */
	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		// do some cleanup
		WSACleanup();
		// then exit
		exit(-1);
	}

	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);

	// structure used in DNS lookups
	struct hostent *remote;
	// structure for connecting to server
	
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(MAGIC_PORT);

	DWORD IP_add = inet_addr(destinationHost);

	if (IP_add == INADDR_NONE)
	{
		// if not a valid IP, then do a DNS lookup
		//DNS lookup performed through a system call
		if ((remote = gethostbyname(destinationHost)) == NULL)
		{
			printf("destination %s is invalid\n", destinationHost);
			//return INVALID_NAME;
			WSACleanup();
			exit(-1);
		}
		else // take the first IP address and copy into sin_addr
			memcpy((char *)&(server.sin_addr), remote->h_addr, remote->h_length);
	}
	else
	{
		// if a valid IP, directly drop its binary version into sin_addr
		server.sin_addr.S_un.S_addr = IP_add;
	}
	printf("Tracerouting to %s...\n", inet_ntoa(server.sin_addr));
	//printf("%d \n", IP_TTL);

#if 1
	for (int count = 1; count <= 30; count++)
	{
		// buffer for the ICMP header
		u_char send_buf[MAX_ICMP_SIZE]; /* IP header is not present here */
		ICMPHeader *icmp = (ICMPHeader *)send_buf;

		// set up the echo request
		// no need to flip the byte order
		icmp->type = ICMP_ECHO_REQUEST;
		icmp->code = 0;

		// set up ID/SEQ fields as needed
		//...
		// set up optional fields as needed
		icmp->id = (u_short)GetCurrentProcessId();
		icmp->seq = count;

		// initialize checksum to zero
		icmp->checksum = 0;
		/* calculate the checksum */
		int packet_size = sizeof(ICMPHeader); // 8 bytes
		icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);

		// set proper TTL
		int ttl = count;

		// need Ws2tcpip.h for IP_TTL, which is equal to 4; there is another constant with the same
		// name in multicast headers – do not use it!
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl)) == SOCKET_ERROR)
		{
			printf("setsockopt failed with %d\n", WSAGetLastError());
			closesocket(sock);
			// some cleanup
			WSACleanup();
			exit(-1);
		}
		// use regular sendto on the above socket
		if (sendto(sock, (char*)send_buf, MAX_ICMP_SIZE, 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
		{
			printf("failed sendto with %d\n", WSAGetLastError());
			WSACleanup();
			exit(-1);
		}
	}
#if 0
	while (true)
	{
		u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
		IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
		ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
		IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
		ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
		fd_set fd;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		timeval tp;
		int initialRTO = 2;
		printf("intial rto %d\n", initialRTO);
		if (initialRTO<1.0)
		{
			tp.tv_sec = 0;
			tp.tv_usec = (long)(initialRTO * 1000 * 1000);
			printf("FIN %ld %ld \n", 0, (long)(initialRTO * 1000 * 1000));
		}
		else
		{
			tp.tv_sec = (long)initialRTO;
			tp.tv_usec = (initialRTO - (long)initialRTO) * 1000 * 1000;
			printf("FIN %ld %ld \n", (long)initialRTO, (initialRTO - (long)initialRTO) * 1000 * 1000);
		}

		struct sockaddr_in response;
		int size = sizeof(response);

		int available = select(0, &fd, NULL, NULL, &tp);
		printf("available %d\n", available);
		if (available > 0)
		{
			int iResult = recvfrom(sock, (char*)&rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &size);
			if (iResult == SOCKET_ERROR)
			{
				//error processing
				printf("failed recvfrom with %d\n", WSAGetLastError());
				WSACleanup();
				exit(-1);
			}
		}
		else if (available == 0)
		{
			//probe count of seq no++;
		}
		else if (available < 0)
		{
			printf("failed with %d on recv\n", WSAGetLastError());
			WSACleanup();
			exit(-1);
		}

		//...
		// check if this is TTL_expired; make sure packet size >= 56 bytes
		printf("here -1");
		if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == 0)
		{
			printf("here 0");
			/*
			https://tools.ietf.org/html/rfc790
			*/
			if (orig_ip_hdr->proto == 1)//ICMP)
			{
				printf("here 2");
				// check if process ID matches
				if (orig_icmp_hdr->id == GetCurrentProcessId())
				{
					//printf("here 3");
					// take router_ip_hdr->source_ip and
					printf("%d %s\n", 1,  router_ip_hdr->source_ip);
					// initiate a DNS lookup
				}
			}
		}
	}
#endif

	// receive from the socket into rec_buf

	
#endif
    return 0;
}

