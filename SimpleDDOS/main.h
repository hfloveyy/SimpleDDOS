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

typedef struct  _ethHeader//物理帧  
{
	BYTE dMac[6];
	BYTE sMac[6];
	USHORT type;
}_EthHeader;

typedef struct _ipHeader//20 字节的IP头部  
{
	BYTE VerAndH_length;//版本号和头部长度  
	BYTE tos;//优先级  
	USHORT totalLength;
	USHORT id;
	USHORT flagANDfrag;//标识和分片  
	BYTE ttl;
	BYTE type;
	USHORT cksum;
	ULONG sIP;
	ULONG dIP;
}IpHeader;

typedef struct _tcpHeader//20 字节的TCP头部  
{
	USHORT sPort;
	USHORT dPort;
	ULONG seq;
	ULONG ack;
	BYTE h_length;//这个值==长度<<2  
	BYTE flag;
	USHORT wsize;//窗口大小  
	USHORT cksum;//tcp头部+伪头部+data  
	USHORT urgpoint;//紧急指针  
	BYTE options[12];
}_TcpHeader;

typedef struct _psdTcp//12字节的伪TCP头部  
{
	ULONG sAddr;
	ULONG dAddr;
	BYTE x;//设为0即可  
	BYTE type;
	USHORT dataLength;
}PsdTcp;



USHORT checksum(USHORT *buffer, int size)//检验IP头部和tcp头部
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

void simpleDD(std::string ip,char* devName);

void getMacbyIp(std::string ip, unsigned char(&mac)[6] );