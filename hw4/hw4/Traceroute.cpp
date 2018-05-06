#include "stdafx.h"
#include "Traceroute.h"

/*
TODO:
error codes handling for routers
dynamic rto calculation
variable sized IP headers
correct start times
if possible send in parallel
reverse dns lookup
*/

/*
Approach:
Send 30 pkts 
and wait for recvd pkts in loop
*/

#define AVAIL 0
#define DBG 0
#define ONLY 0
#define AVAILABLE_ZERO 1
#define ECHO_REPLIED 2
#define CONCURRENT 1

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
		hop_info[i].is_it_destination = false;
	}

	//StartReverseDNSThread();
	StartCounter();
	double start = GetCounter();
	CreateSocket();	
	LookupHost(dest);
#if CONCURRENT
	StartDNSThreads();
#endif
	SendFirstSetofProbes();
	
	/*
	for (int i = 0; i < MAX_HOPS; i++)
	{
		hop_info[i].sent_time= GetCounter();
	}
	*/
	StartReceiving();
	RetxPackets();
	RetxPackets();
#if CONCURRENT
	for (int i = 0; i < MAX_HOPS; i++)
	{
		WaitForSingleObject(dns_params[i]->mutex, INFINITE);
		dns_params[i]->done = true;
		//printf("i %d done signaling\n", i);
		ReleaseMutex(dns_params[i]->mutex);
	}
	for (int i = 0; i < MAX_HOPS; i++)
	{
		//printf("closing");
		//printf("i %d closing\n", i);
		WaitForSingleObject(handles[i], INFINITE);
		CloseHandle(handles[i]);
	}
#endif
	PrintFinalResult();
	printf("Total execution time: %.0f ms\n", GetCounter() - start);
}

Traceroute::~Traceroute()
{
}

UINT reverseDNSLookup(LPVOID pParam)
{
	Parameters *p = (Parameters*)pParam; // shared parameters
	bool flag = true;
	while (flag)
	{
		//printf("loop started\n");
#if 1
		WaitForSingleObject(p->mutex, INFINITE);
		if (p->sourceip > 0)
		{
			//printf("update\n");
			struct in_addr addr;
			addr.S_un.S_addr = p->sourceip;
			char* ip_dot_format = inet_ntoa(addr);
			//char* host = getnamefromip(ip_dot_format);

			/*https://stackoverflow.com/questions/10564525/resolve-ip-to-hostname*/
			char hostname[260];
			char service[260];

			sockaddr_in address;
			memset(&address, 0, sizeof(address));
			address.sin_family = AF_INET;
			address.sin_addr.s_addr = inet_addr(ip_dot_format);
			int response = getnameinfo((sockaddr*)&address,
				sizeof(address),
				hostname,
				260,
				service,
				260,
				0);
			p->ip = ip_dot_format;
			
			if (response == 0)
			{
				//printf("hostname len %d\n", strlen(hostname));
				
				p->host = std::string(hostname);
			}				
			else
			{
				
				std::string tep = "none";
				p->host = tep;
			}
				

			//printf("ip %s host %s\n", p->ip, p->host);
		}
		if (p->done) {
			flag = false;
			//printf("done obtained\n");
		}
		ReleaseMutex(p->mutex);
#endif
	}
	return 0;
	
}

void Traceroute::StartDNSThreads()
{
	for (int i = 0; i < MAX_HOPS; i++)
	{
		//printf("i %d ", i);
		Parameters * p = new Parameters();
		p->mutex = CreateMutex(NULL, 0, NULL);
		p->ip = NULL;
		char t[10] = "hello";
		p->host = t;

		dns_params[i] = p;
		handles[i]= CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)reverseDNSLookup, p, 0, NULL);
		
	}
	return;
}

void Traceroute::CreateSocket()
{
#if DBG
	printf("CreateSocket entry\n");
#endif
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
#if DBG
	printf("LookupHost entry\n");
#endif
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(53);

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

int Traceroute::SendAndRecv(int count, bool first, bool onlySend, bool onlyReceive)
{
#if DBG
	printf("SendAndRecv entry\n");
#endif
	if (onlySend)
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
		hop_info[count - 1].sent_time = GetCounter();
		hop_info[count - 1].probes_sent++;

		if (sendto(sock, (char*)icmp, sizeof(ICMPHeader), 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
		{
			printf("failed sendto with %d\n", WSAGetLastError());
			WSACleanup();
			exit(-1);
		}
	}
	
	if (onlyReceive)
	{
		fd_set fd;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		timeval tp;

		double initialRTO;
		if (first)
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
#if ONLY
		printf("initialRTO %ld sec %ld microsec \n", tp.tv_sec, tp.tv_usec);
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
#if AVAIL
			printf("router_icmp_hdr->type %d\n", (router_icmp_hdr->type));
#endif
			// check if this is TTL_expired; make sure packet size >= 56 bytes
#if ONLY
			if (iResult >= 28)
			{
				printf("LOL router_icmp_hdr seq %d code %d type %d \n", router_icmp_hdr->seq, router_icmp_hdr->code, router_icmp_hdr->type);
			}
			if (iResult >= 56)
			{
				printf("HEHE orig_icmp_hdr seq %d code %d type %d \n\n", orig_icmp_hdr->seq, orig_icmp_hdr->code, orig_icmp_hdr->type);
			}
#endif
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
#if AVAIL
						printf("hop %d %d.%d.%d.%d ", seq + 1, a[0], a[1], a[2], a[3]);
#endif
#if 0
						printf("orig_icmp_hdr seq %d code %d type %d \n", orig_icmp_hdr->seq, orig_icmp_hdr->code, orig_icmp_hdr->type);
						
#endif
						double st, en;
						hop_info[seq].recvd_time = GetCounter();
						st = hop_info[seq].sent_time;
						en = hop_info[seq].recvd_time;
						hop_info[seq].RTO = en - st;
						hop_info[seq].orig_icmp_hdr = orig_icmp_hdr;
						hop_info[seq].ip = router_ip_hdr->source_ip;
#if CONCURRENT
						WaitForSingleObject(dns_params[seq]->mutex, INFINITE);
						dns_params[seq]->sourceip = temp;
						ReleaseMutex(dns_params[seq]->mutex);
#endif
						/**/
#if AVAIL
						printf("end-start %.3f ms\n", en - st);
#endif
						// initiate a DNS lookup
						//break;
					}
				}
			}
			else if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == 0 && iResult >= 56)
			{
				if (orig_ip_hdr->proto == 1 && orig_icmp_hdr->id == (u_short)GetCurrentProcessId())
				{
					//printf("reached final destination\n\n\n");
					//printf("reached final destination\n\n\n");
					u_long temp = (router_ip_hdr->source_ip);
					u_char *a = (u_char*)&temp;
					int seq = orig_icmp_hdr->seq - 1;
#if AVAIL
					printf("hop %d %d.%d.%d.%d ", seq + 1, a[0], a[1], a[2], a[3]);
#endif
#if DBG
					//printf("orig_icmp_hdr seq %d code %d type %d \n", orig_icmp_hdr->seq, orig_icmp_hdr->code, orig_icmp_hdr->type);
#endif
					double st, en;
					hop_info[seq].recvd_time = GetCounter();
					st = hop_info[seq].sent_time;
					en = hop_info[seq].recvd_time;
					hop_info[seq].RTO = en - st;
					hop_info[seq].orig_icmp_hdr = orig_icmp_hdr;
					hop_info[seq].ip = router_ip_hdr->source_ip;
					hop_info[seq].is_it_destination = true;
#if CONCURRENT
					WaitForSingleObject(dns_params[seq]->mutex, INFINITE);
					dns_params[seq]->sourceip = temp;
					ReleaseMutex(dns_params[seq]->mutex);
#endif
					/**/
#if AVAIL
					printf("end-start %.3f ms\n", en - st);
#endif
					//printf("reply received");
					//return ECHO_REPLIED;
				}
			}
			else if(iResult < 56)
			{
					//only router icmp and ip hdrs are present
					//determine if it is echo reply
					//and obtain the source ip
				if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == 0)
				{
					//printf("reached final destination\n\n\n");
					u_long temp = (router_ip_hdr->source_ip);
					u_char *a = (u_char*)&temp;
					
					//error here
					int seq = router_icmp_hdr->seq - 1;
#if AVAIL
					printf("hop %d %d.%d.%d.%d ", seq + 1, a[0], a[1], a[2], a[3]);
#endif
#if 0
					printf("router_icmp_hdr seq %d code %d type %d \n", router_icmp_hdr->seq, router_icmp_hdr->code, router_icmp_hdr->type);
					//printf("orig_icmp_hdr seq %d code %d type %d \n", orig_icmp_hdr->seq, orig_icmp_hdr->code, orig_icmp_hdr->type);
#endif
					double st, en;
					hop_info[seq].recvd_time = GetCounter();
					st = hop_info[seq].sent_time;
					en = hop_info[seq].recvd_time;
					hop_info[seq].RTO = en - st;
					hop_info[seq].orig_icmp_hdr = orig_icmp_hdr;
					hop_info[seq].ip = router_ip_hdr->source_ip;
					hop_info[seq].is_it_destination = true;
#if CONCURRENT
					WaitForSingleObject(dns_params[seq]->mutex, INFINITE);
					dns_params[seq]->sourceip = temp;
					ReleaseMutex(dns_params[seq]->mutex);
#endif
					/**/
#if AVAIL
					printf("end-start %.3f ms\n", en - st);
#endif
					//printf("reply received");
					//return ECHO_REPLIED;
				}
			}
#if 0
			//error checking for invalid code and types
			else
			{
				if (orig_ip_hdr->proto == 1 && orig_icmp_hdr->id == (u_short)GetCurrentProcessId() && iResult >= 56)
				{

				}
			}
#endif
		}
		else if (available == 0)
		{
			//probe count of seq no++;
			//i++;
			return AVAILABLE_ZERO;
		}
		else if (available < 0)
		{
			printf("failed with %d on recv\n", WSAGetLastError());
			WSACleanup();
			exit(-1);
		}
	}
	return 0;
}

void Traceroute::SendFirstSetofProbes()
{
#if DBG
	printf("SendFirstSetofProbes entry %f \n",GetCounter());
#endif
	for (int count = 1; count <= MAX_HOPS; count++)
	{
		int ret = SendAndRecv(count, true, true, false);
	}
#if DBG
	printf("SendFirstSetofProbes exit %f \n", GetCounter());
#endif
}

void Traceroute::StartReceiving()
{
	while (true)
	{
		//if echo reply then break the loop
		int ret = SendAndRecv(-1, true, false, true);
		//printf("ret %d\n", ret);
		if (ret == AVAILABLE_ZERO)
		{
			//printf("echo reply here\n");
			break;
		}
			
	}
}

void Traceroute::RetxPackets()
{
#if DBG
	printf("\nRetxPackets entry\n");
#endif
	bool flag = true;
	for (int i = 0; i < MAX_HOPS && flag; i++)
	{
		//printf("i %d rto %f\n", i, hop_info[i].RTO);
		if (hop_info[i].is_it_destination)
			flag = false;
		if (hop_info[i].probes_sent < 3 && hop_info[i].RTO < 0 )
		{
			//printf("\nretx count %d here\n", i+1);
			int count = i + 1;
			//send packet
			//increase probe count
			//update sent time
			int ret = SendAndRecv(count, false, true, false);
			ret = SendAndRecv(count, false, false, true);
			//printf("retx ret val %d\n", ret);
		}
	}
}

void Traceroute::PrintFinalResult()
{
	printf("printing final result\n");
	bool flag = true;
	for (int i = 0; i < MAX_HOPS && flag; i++)
	{
		if (hop_info[i].is_it_destination)
			flag = false;
		if (hop_info[i].RTO < 0 )
		{
			printf("%d *\n", i + 1);
		}
		else
		{
#if CONCURRENT
			//printf("i %d here\n", i);
			WaitForSingleObject(dns_params[i]->mutex, INFINITE);
#if 0
			if (dns_params[i]->host == "none")
			{
				printf("host is NULL");
			}
			else
			{
				//printf("not null len %d\n", strlen(dns_params[i]->host));
				printf("\nhost %s\n", dns_params[i]->host.c_str());
			}
#endif
			//printf("\n%s %s\n", dns_params[i]->host, dns_params[i]->ip);
			if (dns_params[i]->host == "none" || strcmp(dns_params[i]->host.c_str(), dns_params[i]->ip)==0)
				printf("%d <no DNS entry> (%s) %.3f ms (%d)\n", i + 1, dns_params[i]->ip, hop_info[i].RTO, hop_info[i].probes_sent);
			else
			{
				printf("%d %s (%s) %.3f ms (%d)\n", i + 1, dns_params[i]->host.c_str(), dns_params[i]->ip, hop_info[i].RTO, hop_info[i].probes_sent);
			}
			ReleaseMutex(dns_params[i]->mutex);
#else
			u_long temp = hop_info[i].ip;
			struct in_addr addr;
			addr.S_un.S_addr = temp;
			char* ip_dot_format = inet_ntoa(addr);
			//char* host = getnamefromip(ip_dot_format);

			/*https://stackoverflow.com/questions/10564525/resolve-ip-to-hostname*/
			char hostname[260];
			char service[260];

			sockaddr_in address;
			memset(&address, 0, sizeof(address));
			address.sin_family = AF_INET;
			address.sin_addr.s_addr = inet_addr(ip_dot_format);
			int response = getnameinfo((sockaddr*)&address,
				sizeof(address),
				hostname,
				260,
				service,
				260,
				0);
			if(strcmp(ip_dot_format, hostname) == 0 || response != 0)
				printf("%d <no DNS entry> (%s) %.3f ms (%d)\n", i + 1, ip_dot_format, hop_info[i].RTO, hop_info[i].probes_sent);
			else
			{
				printf("%d %s (%s) %.3f ms (%d)\n", i + 1, hostname, ip_dot_format, hop_info[i].RTO, hop_info[i].probes_sent);
			}
#endif
				
			
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
