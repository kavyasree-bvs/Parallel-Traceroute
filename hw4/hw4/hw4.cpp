// hw4.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Traceroute.h"

/*REFERENCES:
https://stackoverflow.com/questions/1739259/how-to-use-queryperformancecounter

*/
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
	
	WSADATA wsaData;
	WORD wVersionRequested;
	//Initialize WinSock; once per program run
	wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) 
	{
		printf("WSAStartup error %d\n", WSAGetLastError());
		exit(0);
	}

	Traceroute tr = Traceroute(destinationHost);
    return 0;
}

