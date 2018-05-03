#define WIN32
#pragma once

#include <string>
#include <iostream>
#include <csignal>
#include <winsock2.h> 

#include <Iphlpapi.h>
#include <thread>
#include "pcap.h"

#pragma comment(lib, "wpcap.lib")  
#pragma comment(lib, "ws2_32.lib")  
#pragma comment (lib, "Iphlpapi")

#define SEQ 0x28376839  

typedef struct  _ethHeader//����֡  
{
	BYTE dMac[6];
	BYTE sMac[6];
	USHORT type;
}_EthHeader;

typedef struct _ipHeader//20 �ֽڵ�IPͷ��  
{
	BYTE VerAndH_length;//�汾�ź�ͷ������  
	BYTE tos;//���ȼ�  
	USHORT totalLength;
	USHORT id;
	USHORT flagANDfrag;//��ʶ�ͷ�Ƭ  
	BYTE ttl;
	BYTE type;
	USHORT cksum;
	ULONG sIP;
	ULONG dIP;
}IpHeader;

typedef struct _tcpHeader//20 �ֽڵ�TCPͷ��  
{
	USHORT sPort;
	USHORT dPort;
	ULONG seq;
	ULONG ack;
	BYTE h_length;//���ֵ==����<<2  
	BYTE flag;
	USHORT wsize;//���ڴ�С  
	USHORT cksum;//tcpͷ��+αͷ��+data  
	USHORT urgpoint;//����ָ��  
	BYTE options[12];
}_TcpHeader;

typedef struct _psdTcp//12�ֽڵ�αTCPͷ��  
{
	ULONG sAddr;
	ULONG dAddr;
	BYTE x;//��Ϊ0����  
	BYTE type;
	USHORT dataLength;
}PsdTcp;



USHORT checksum(USHORT *buffer, int size)//����IPͷ����tcpͷ��
{
	unsigned long cksum = 0;
	while (size >1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
void simpleDD(std::string ip,char* devName,char* myIp,int port);

void getMacbyIp(std::string ip, unsigned char(&mac)[6] );