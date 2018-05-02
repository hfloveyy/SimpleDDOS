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

void simpleDD(std::string ip,char* devName);

void getMacbyIp(std::string ip, unsigned char(&mac)[6] );