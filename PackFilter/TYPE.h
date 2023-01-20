//ip数据报首部格式
typedef struct 
{
	union
	{
		unsigned char Version;
		unsigned char HeadLen;
	};
	unsigned char  Tos;
	unsigned short TotalLen;
	unsigned short Ident;
	union
	{
		unsigned short Flags;
		unsigned short FragOffset;
	};
	unsigned char  Ttl;
	unsigned char  Protocol;
	unsigned short HeadChecksum;
	unsigned int   SourceIP;
	unsigned int   DestIP;
}IP_HEAD;

//TCP报文段的首部格式
typedef struct 
{
	unsigned short SourcePort;
	unsigned short DestPort;
	unsigned int   Serialnum;
	unsigned int   Ack;
	union 
	{
		unsigned short HeadLen;
		unsigned short Keep;
		unsigned short codeBit;
	};
	unsigned short Windows;
        unsigned short CheckSum;
	unsigned short Urgentpoint;
}TCP_HEAD;

//UDP报文段的首部格式
typedef struct 
{
	unsigned short SourcePort;
	unsigned short DestPort;
	unsigned short UdpPackLen;
    unsigned short CheckSum;
}UDP_HEAD;

//定义包过滤表结构
typedef struct
{
	char SourceAddr[16];
	char DestinAddr[16];
	unsigned short SourcePort;
	unsigned short DestinPort;
	unsigned char Protocol;
	bool Operation;
}filter_table;

#define PACK_SIZE  sizeof(IP_HEAD) //