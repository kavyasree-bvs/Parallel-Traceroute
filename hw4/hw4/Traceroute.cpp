#include "stdafx.h"
#include "Traceroute.h"

/*
TODO:
error codes handling
dynamic rto calculation
*/
Traceroute::Traceroute(char* dest)
{
	printf("traceroute constr entry\n");
	//destName = dest;
	CreateSocket();	
	LookupHost(dest);
	SendFirstSetofProbes();
	StartReceivingPackets();
}

Traceroute::~Traceroute()
{
}

void Traceroute::CreateSocket()
{
	printf("CreateSocket entry\n");
	/* ready to create a socket */
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		// do some cleanup
		WSACleanup();
		// then exit
		exit(-1);
	}
}

void Traceroute::LookupHost(char* destinationHost)
{
	printf("LookupHost entry\n");
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	
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
}

void Traceroute::SendFirstSetofProbes()
{
	printf("SendFirstSetofProbes entry\n");
	for (int count = 1; count <= MAX_HOPS; count++)
	{
		//printf("SendFirstSetofProbes count = %d\n", count);
		
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
		printf("\nttl %x\n", ttl);

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
		for (int i = 1; i <= 3;)
		{
			// use regular sendto on the above socket
			printf("\nattempt %d out of 3\n", i);
			if (sendto(sock, (char*)send_buf, MAX_ICMP_SIZE, 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
			{
				printf("failed sendto with %d\n", WSAGetLastError());
				WSACleanup();
				exit(-1);
			}
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

			u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
			IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
			ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
			IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
			ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
			
			int available = select(0, &fd, NULL, NULL, &tp);
			printf("available %d\n", available);
			int iResult = 0;
			
			if (available > 0)
			{
				iResult = recvfrom(sock, (char*)&rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &size);
				printf("iResult %d\n", iResult);
				if (iResult == SOCKET_ERROR)
				{
					//error processing
					printf("failed recvfrom with %d\n", WSAGetLastError());
					WSACleanup();
					exit(-1);
				}
				// check if this is TTL_expired; make sure packet size >= 56 bytes
				if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == 0 && iResult >= 56)
				{
					//printf("here 0");
					/*
					https://tools.ietf.org/html/rfc790
					*/
					if (orig_ip_hdr->proto == 1)//ICMP)
					{
						// check if process ID matches
						if (orig_icmp_hdr->id == (u_short)GetCurrentProcessId())
						{
							// take router_ip_hdr->source_ip and
							//printf("\tip %d\n", router_ip_hdr->source_ip);
							u_long temp = (router_ip_hdr->source_ip);
							u_char *a = (u_char*)&temp;
							printf("\t\t\t\t%d.%d.%d.%d\n", a[0],a[1],a[2],a[3]);
							printf("orig_icmp_hdr code %d type %d \n", orig_icmp_hdr->code, orig_icmp_hdr->type);
							printf("orig_icmp_hdr seq %d \n", orig_icmp_hdr->seq);
							//printf("orig_ip_hdr->ttl %x\n", orig_ip_hdr->ttl);
							//printf("router_ip_hdr->ttl %x\n", router_ip_hdr->ttl);
							// initiate a DNS lookup
							break;
						}
					}
					else if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == 0 && iResult >= 56)
					{
						if (orig_ip_hdr->proto == 1 && orig_icmp_hdr->id == (u_short)GetCurrentProcessId())
						{
							printf("reached final destination\n\n\n");
							
						}
					}
				}
			}
			else if (available == 0)
			{
				//probe count of seq no++;
				i++;

			}
			else if (available < 0)
			{
				printf("failed with %d on recv\n", WSAGetLastError());
				//WSACleanup();
				//exit(-1);
			}
		}
		
		
	}
}

void Traceroute::StartReceivingPackets()
{
	
	
	while (false)
	{
		

		//...
		
	}
	

}


/*
* ======================================================================
* ip_checksum: compute Internet checksums
*
* Returns the checksum. No errors possible.
*
* ======================================================================
*/
u_short Traceroute::ip_checksum(u_short *buffer, int size)
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
