#include <stdio.h>
#include <iostream>
#include <winsock2.h>
#include <WS2TCPIP.h>
#include <MSTCPIP.h>
#include "TYPE.h"

using namespace std;
#pragma comment(lib,"WS2_32.lib")

int main(void)
{

	//SetConsoleCtrlHandler()
	int err;
	WSAData wsaData;

	err = WSAStartup(MAKEWORD(2,2),&wsaData);//WSAStartup(WINSOCK_VERSION,&wsaData);
    if(0 != err)
	{
		cout<<err<<endl;
		return -1;
	}

	SOCKET sock;
	sock = socket(AF_INET,SOCK_RAW,IPPROTO_IP);//通过网卡截获并分析IP数据包采用raw原始套接字
	if(INVALID_SOCKET == sock)
	{
		err = GetLastError();
		cout<<err<<endl;
		WSACleanup();
		return -1;
	}

	char hostName[128];
	err = gethostname(hostName,sizeof(hostName));//获取本地主机名
	if(0 != err)
	{
		err = GetLastError();
		cout<<err<<endl;
		closesocket(sock);
		WSACleanup();
		return -1;
	}

	HOSTENT *pHostIP = NULL;
	pHostIP = gethostbyname(hostName);//获取IP列表
	if(NULL == pHostIP)
	{
		err = GetLastError();
		cout<<err<<endl;
        closesocket(sock);
		WSACleanup();
		return -1;
	}
    

	struct sockaddr_in sockAddr;     //本地地址
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port   = htons(6666);
	sockAddr.sin_addr = *(in_addr*)pHostIP->h_addr_list[1];//S_un.S_addr
    
	cout<<"Local IpAddress\t"<<inet_ntoa(sockAddr.sin_addr)<<endl;

	err = bind(sock,(struct sockaddr*)&sockAddr,sizeof(sockAddr));//绑定
	if(0 != err)
	{
		err = GetLastError();
		cout<<err<<endl;
		closesocket(sock);
		WSACleanup();
		return -1;
	}

	/*通常，网卡不能接收mac地址不是自己的IP数据包，要想能
	捕获所有IP数据包，应该先将网卡的工作模式设置为“混杂”*/
	//DWORD dwBufferLen[10]; 
	//DWORD dwBufferInLen=1; 
	DWORD dwBytesReturned=0; 
 	//err = WSAIoctl(sock,SIO_RCVALL,&dwBufferInLen,sizeof(dwBufferInLen),
	//dwBufferLen,sizeof(dwBufferLen),&dwBytesReturned,NULL,NULL);
	int on = RCVALL_ON;
	err = WSAIoctl(sock,SIO_RCVALL,&on,sizeof(on),
		NULL,0,&dwBytesReturned,NULL,NULL);
    if(0 != err)
	{
		cout<<""<<endl;
	}
    
	int recvbuffLen;
    int len = sizeof(recvbuffLen);
    getsockopt(sock,SOL_SOCKET,SO_RCVBUF,(char*)&recvbuffLen,&len);   //获取缓冲与大小

	char    *buffer =  (char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,recvbuffLen);
    IP_HEAD *pIpHead = (IP_HEAD *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(IP_HEAD));
	TCP_HEAD*pTcpHead= (TCP_HEAD*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(TCP_HEAD));
	UDP_HEAD*pUdpHead= (UDP_HEAD*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(UDP_HEAD));
	struct in_addr sourceIP;   //源地址
	struct in_addr destIP;     //目地地址
    unsigned char  HeadLen = 0;
	unsigned short TotalLen= 0;
	while(TRUE)
	{
		memset(buffer,'\0',recvbuffLen);
		err = recvfrom(sock,buffer,recvbuffLen,0,NULL,NULL);
		if(err == SOCKET_ERROR)
		{
			err = GetLastError();
			cout<<err<<endl;
			break;
		}
		memcpy(pIpHead,buffer,((((IP_HEAD *)buffer)->HeadLen)));
		memcpy(&destIP,&(pIpHead->DestIP),sizeof(in_addr));
		memcpy(&sourceIP,&(pIpHead->SourceIP),sizeof(in_addr));
	    HeadLen = ((pIpHead->HeadLen)&0x0f)*4;
       TotalLen= pIpHead->TotalLen;
        
		//cout<<"PACKAGE_HEAD_LENGHT:"<<(int)HeadLen<<endl;
		//cout<<"PACKAGE_TOTAL_LENGHT:"<<TotalLen<<endl;
		switch(((IP_HEAD *)buffer)->Protocol)
		{
		case IPPROTO_ICMP:
			cout<<"ICMP From\t"<<inet_ntoa(sourceIP);
			cout<<"\tTo\t"<<inet_ntoa(destIP)<<endl;
			break;
		case IPPROTO_IGMP:
			cout<<"IGMP From\t"<<inet_ntoa(sourceIP);
			cout<<"\tTo\t"<<inet_ntoa(destIP)<<endl;
			break;
		case IPPROTO_TCP:
            memcpy(pTcpHead,buffer+HeadLen,sizeof(TCP_HEAD));//注意字节序问题
			cout<<"TCP From\t"<<inet_ntoa(sourceIP)<<": "<<ntohs(pTcpHead->SourcePort);
			cout<<"\tTo\t"<<inet_ntoa(destIP)<<": "<<ntohs(pTcpHead->DestPort);
			if(ntohs(pTcpHead->codeBit)&0x0002)
            cout<<" SYN";
            if(ntohs(pTcpHead->codeBit)&0x0001)
			cout<<" FIN";
            if(ntohs(pTcpHead->codeBit)&0x0010)
			cout<<" ACK";
			cout<<endl;
			break;
		case IPPROTO_UDP:
			memcpy(pUdpHead,buffer+HeadLen-1,sizeof(UDP_HEAD));//注意字节序问题
			cout<<"UDP From\t"<<inet_ntoa(sourceIP)<<": "<<ntohs(pUdpHead->SourcePort);
			cout<<"\tTo\t"<<inet_ntoa(destIP)<<": "<<ntohs(pUdpHead->DestPort)<<endl;
			break;
		}
	}
    HeapFree(GetProcessHeap(),0,(LPVOID)buffer);
	HeapFree(GetProcessHeap(),0,(LPVOID)pTcpHead);
	HeapFree(GetProcessHeap(),0,(LPVOID)pIpHead);
	HeapFree(GetProcessHeap(),0,(LPVOID)pUdpHead);
	closesocket(sock);
	WSACleanup();
	return 0;
}
