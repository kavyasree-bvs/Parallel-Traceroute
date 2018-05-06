#include "stdafx.h"
#include "Traceroute.h"

/*
TODO:
error codes handling
dynamic rto calculation
*/

/*
Approach:
Send 30 pkts 
and wait for recvd pkts in loop
*/

#define AVAIL 0
double PCFreq = 0.0;
__int64 CounterStart = 0;
void StartCounter()
{
	LARGE_INTEGER li;
	if (!QueryPerformanceFrequency(&li))
		printf("QueryPerformanceFrequency failed!\n");

	PCFreq = double(li.QuadPart) / 1000.0;

	QueryPerformanceCounter(&li);
	CounterStart = li.QuadPart;
}

double GetCounter()
{
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	return double(li.QuadPart - CounterStart) / PCFreq;
}

Traceroute::Traceroute(char* dest)
{
#if DBG
	printf("traceroute constr entry\n");
#endif
	for (int i = 0; i < MAX_HOPS; i++)
	{
		hop_info[i].sent_time = -1;
		hop_info[i].recvd_time = -1;
		hop_info[i].probes_sent = 0;
		hop_info[i].RTO = -1;
	}
	StartCounter();
	CreateSocket();	
	LookupHost(dest);
	SendFirstSetofProbes();
#if 1	
	RetxPackets();
	RetxPackets();
	PrintFinalResult();
#endif
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

double Traceroute::SetDynamicRTO(int index)
{
	double pred_rto = -1;
	double suc_rto = -1;

	for (int i = index - 1; i >= 0; i--)
	{
		if (hop_info[i].RTO > 0) {
			pred_rto = hop_info[i].RTO;
			break;
		}			
	}
	for (int j = index + 1; j < MAX_HOPS; j++)
	{
		if (hop_info[j].RTO > 0) {
			pred_rto = hop_info[j].RTO;
			break;
		}
	}

	if (pred_rto != -1 && suc_rto == -1)
	{
#if AVAIL
		printf("no successor\n");
#endif
		for (int i = 0; i < index; i++)
		{
			if (pred_rto < hop_info[i].RTO)
				pred_rto = hop_info[i].RTO;
		}
		/**/
		return 2 * pred_rto;
	}
	if (suc_rto != -1 && pred_rto == -1)
	{
#if AVAIL
		printf("no predecessor\n");
#endif
		return 2 * suc_rto;
	}
	if (suc_rto != -1 && pred_rto != -1)
	{
#if AVAIL
		printf("adjacent entries present\n");
#endif
		return (pred_rto + suc_rto);
	}
	return DEFAULT_TIMEOUT;
}

#if 1
void Traceroute::SendAndRecv(int count, bool first)
{
#if DBG
	printf("SendAndRecv entry\n");
#endif
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
#if DBG
	printf("\nttl %d icmp->type %d icmp->code %d icmp->seq %d\n", ttl, icmp->type, icmp->code, icmp->seq);
#endif
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
	hop_info[count - 1].probes_sent++;
	hop_info[count - 1].sent_time = GetCounter();
	
	fd_set fd;
	FD_ZERO(&fd);
	FD_SET(sock, &fd);
	timeval tp;
	
	double initialRTO;
	if(first)
		initialRTO = DEFAULT_TIMEOUT;//in ms
	else
		initialRTO = SetDynamicRTO(count - 1);
		
	initialRTO = initialRTO / 1000;

	if (initialRTO<1.0)
	{
		tp.tv_sec = 0;
		tp.tv_usec = (long)(initialRTO * 1000 * 1000);
	}
	else
	{
		tp.tv_sec = (long)initialRTO;
		tp.tv_usec = (long)(initialRTO - (long)initialRTO) * 1000 * 1000;
	}
#if DBG
	printf("initialRTO %ld s %ld microsec \n", tp.tv_sec, tp.tv_usec);
#endif

	struct sockaddr_in response;
	int size = sizeof(response);

	u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

	int available = select(0, &fd, NULL, NULL, &tp);
#if AVAIL
	printf("select available %d\n", available);
#endif

	int iResult = 0;

	if (available > 0)
	{
		iResult = recvfrom(sock, (char*)&rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &size);
#if AVAIL
		printf("iResult %d\n", iResult);
#endif
		if (iResult == SOCKET_ERROR)
		{
			//error processing
			printf("failed recvfrom with %d\n", WSAGetLastError());
			WSACleanup();
			exit(-1);
		}
		//printf("(router_icmp_hdr->type %d\n", (router_icmp_hdr->type));
		// check if this is TTL_expired; make sure packet size >= 56 bytes
		if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == 0 && iResult >= 56)
		{
			/*https://tools.ietf.org/html/rfc790*/
			if (orig_ip_hdr->proto == 1)//ICMP)
			{
				// check if process ID matches
				if (orig_icmp_hdr->id == (u_short)GetCurrentProcessId())
				{
					// take router_ip_hdr->source_ip and
					//printf("\tip %d\n", router_ip_hdr->source_ip);
					u_long temp = (router_ip_hdr->source_ip);
					u_char *a = (u_char*)&temp;
					int seq = orig_icmp_hdr->seq - 1;
					printf("hop %d %d.%d.%d.%d ", seq+1, a[0], a[1], a[2], a[3]);
#if DBG
					printf("orig_icmp_hdr seq %d code %d type %d \n", orig_icmp_hdr->seq, orig_icmp_hdr->code, orig_icmp_hdr->type);
#endif
					
					double st, en;
					hop_info[seq].recvd_time = GetCounter();
					st = hop_info[seq].sent_time;
					en = hop_info[seq].recvd_time;
					hop_info[seq].RTO = en - st;
					hop_info[seq].orig_icmp_hdr = orig_icmp_hdr;
					hop_info[seq].ip = router_ip_hdr->source_ip;
					printf("start %.3f end %.3f end-start %.3f ms\n", st, en, en - st);

					// initiate a DNS lookup
					//break;
				}
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
	else if (available == 0)
	{
		//probe count of seq no++;
		//i++;
	}
	else if (available < 0)
	{
		printf("failed with %d on recv\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
}
#endif

void Traceroute::SendFirstSetofProbes()
{
#if DBG
	printf("SendFirstSetofProbes entry %f \n",GetCounter());
#endif
	for (int count = 1; count <= MAX_HOPS; count++)
	{
		SendAndRecv(count, true);
	}
#if DBG
	printf("SendFirstSetofProbes exit %f \n", GetCounter());
#endif
}

void Traceroute::RetxPackets()
{
#if DBG
	printf("\nRetxPackets entry\n");
#endif
	for (int i = 0; i < MAX_HOPS; i++)
	{
		//printf("i %d rto %f\n", i, hop_info[i].RTO);
		if (hop_info[i].probes_sent < 3 && hop_info[i].RTO < 0)
		{
			//printf("here");
			int count = i + 1;
			//send packet
			//increase probe count
			//update sent time
			SendAndRecv(count, false);
		}
	}
}

void Traceroute::PrintFinalResult()
{
	for (int i = 0; i < MAX_HOPS; i++)
	{
		if (hop_info[i].RTO < 0)
		{
			printf("%d *\n", i + 1);
		}
		else
		{
			u_long temp = hop_info[i].ip;
			struct in_addr addr;
			addr.S_un.S_addr = temp;
			char* ip_dot_format = inet_ntoa(addr);
			printf("%d (%s)\t%.3f ms (%d)\n", i + 1, ip_dot_format, hop_info[i].RTO, hop_info[i].probes_sent);
		}
	}
}

char* Traceroute::LookupDNS(u_long ip)
{
	struct in_addr addr;
	addr.S_un.S_addr = ip;
	char* ip_dot_format = inet_ntoa(addr);
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
