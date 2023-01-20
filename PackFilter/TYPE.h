//ip���ݱ��ײ���ʽ
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

//TCP���Ķε��ײ���ʽ
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

//UDP���Ķε��ײ���ʽ
typedef struct 
{
	unsigned short SourcePort;
	unsigned short DestPort;
	unsigned short UdpPackLen;
    unsigned short CheckSum;
}UDP_HEAD;

//��������˱�ṹ
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