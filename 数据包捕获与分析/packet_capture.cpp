//#include <iostream>
//#include <pcap.h>
//using namespace std;
//
//int main() {
//    char err[PCAP_ERRBUF_SIZE];
//    pcap_if_t* alldevs;
//
//    if (pcap_findalldevs(&alldevs, err) == -1) {
//        cout << "Error in pcap_findalldevs: " << err << endl;
//        return 1;
//    }
//    for (pcap_if_t* device = alldevs; device != NULL; device = device->next) {
//        cout << "Device Name: " << device->name << endl;
//        if (device->description)
//           cout << "Description: " << device->description << endl;
//        cout << endl;
//    }
//    pcap_freealldevs(alldevs);
//    return 0;
//}
//



//#include <pcap.h>
//using namespace std;
//#include<iostream>
//int main() {
//    char errbuf[PCAP_ERRBUF_SIZE];//用以接受错误信息
//    const char* deviceName = "\\Device\\NPF_{D09A091D-5ED5-4F08-A9DC-A83D8E552330}";//用IPv6 网络通信的 WAN Miniport 设备进行测试
//    pcap_t* dev;
//
//    dev = pcap_open_live(deviceName, 65535, 1, 1000, errbuf);
//
//    if (dev == NULL) {
//        cout<<"Could not open" <<deviceName;
//        return 1;
//    }
//    else {
//        cout << "you succeed";
//    }
//    // 成功打开网卡设备，可以开始捕获数据包
//
//    pcap_close(dev);
//    
//    return 0;
//}



//#include <pcap.h>
//#include <iostream>
//using namespace std;
//
//int main() {
//    int device_num = 0;
//    pcap_if_t* alldevs;
//    char err[PCAP_ERRBUF_SIZE]; // 用以接受错误信息
//
//    if (pcap_findalldevs(&alldevs, err) == -1) {
//        cerr << "Error in pcap_findalldevs: " << err << endl;
//        return 1;
//    }
//
//    for (pcap_if_t* device = alldevs; device != nullptr; device = device->next) {
//        cout << "Device Name: " << device->name << endl;
//        device_num++;
//        if (device->description)
//            cout << "Description: " << device->description << endl;
//        cout << endl;
//    }
//    cout << "Total devices: " << device_num << endl;
//
//    int device_number;
//    cout << "请输入要查找的设备: ";
//    cin >> device_number;
//
//    if (device_number >= device_num) {
//        cerr << "无效的设备编号" << endl;
//        pcap_freealldevs(alldevs);
//        return 1;
//    }
//    pcap_if_t* device = alldevs;
//    for (int i = 0; i < device_number; i++) {
//        device = device->next;
//    }
//    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, err);
//    while (true) {
//        struct pcap_pkthdr* header;
//        const u_char* packet;
//        int result = pcap_next_ex(handle, &header, &packet);
//        if (result == 1) {
//            cout << "===== Got a packet with length of " << header->len << " =====" << endl;
//            // 打印数据包的简要信息
//            for (int i = 0; i < header->len; i++) {
//                cout << hex << (int)packet[i] << " ";
//            }
//            cout << endl;
//        }
//        else if (result == 0) {
//            // 未收到数据包，继续捕获。
//        }
//        else if (result == -1) {
//            cerr << "pcap_next_ex error: " << pcap_geterr(handle) << endl;
//            break;
//        }
//        else if (result == -2) {
//            cerr << "结束" << endl;
//            break;
//        }
//    }
//    pcap_freealldevs(alldevs);
//    pcap_close(handle);
//    return 0;
//}


#include<iostream>
#include "pcap.h"
#include <string>
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable : 4996)
using namespace std;

class Frame {
public:
	uint8_t DesMAC[6];  // 目的地址
	uint8_t SrcMAC[6];  // 源地址
	uint16_t FrameType; // 帧类型
};

class IPHead {
public:
	uint8_t Ver_HLen;      // IP协议版本和IP首部长度
	uint16_t TotalLen;     // 总长度
	uint8_t TTL;           // 生存周期
	uint8_t Protocol;      // 协议
	uint16_t Checksum;     // 头部校验和
	uint32_t SrcIP;        // 源IP
	uint32_t DstIP;        // 目的IP
};

class Data {
public:
	Frame FrameHeader;
	IPHead IPHeader;
};



void PacketHandle(u_char*, const struct pcap_pkthdr*, const u_char*);
void IP_Packet_Handle(const struct pcap_pkthdr*, const u_char*);

int main()
{
	pcap_if_t* devs;//指向设备链表首部的指针
	pcap_if_t* f;
	char err[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int device_num = 0;//接口数量
	int n;
	int read_count;
	//获得本机的设备列表
	if (pcap_findalldevs(&devs, err) == -1)
	{
		//错误处理
		cout << "错误信息" << err << endl;
		pcap_freealldevs(devs);
		return 0;
	}
	//显示接口列表
	for (f = devs; f != NULL; f = f->next)
	{
		device_num++;
		cout << dec << device_num << ":" << f->name << endl;
		if (f->description != NULL)
		{
			cout << f->description << endl;
		}
		else
		{
			return -1;
		}
	}
	cout << "请输入设备号" << endl;
	cin >> n;
	if (n > device_num) {
		cout << "输入错误" << endl;
		return -1;
	}
	device_num = 0;
	for (f = devs; device_num < (n - 1); device_num++)
	{
		f = f->next;
	}
	pcap_t* handle;
	handle = pcap_open_live(f->name, 65536, 1, 1000, NULL);
	if (handle == NULL)
	{
		cout << "打开设备失败" << endl;
		pcap_freealldevs(devs);
		return 0;
	}


	pcap_loop(handle, 5, (pcap_handler)PacketHandle, NULL);
	pcap_close(handle);
	return 0;
}

void PacketHandle(u_char* argunment, const struct pcap_pkthdr* pkt_head, const u_char* pkt_data)
{
	Frame* ethernet_protocol;		//以太网协议
	u_short ethernet_type;		//以太网类型
	u_char* mac_addr;			//以太网地址
	//获取以太网数据内容
	ethernet_protocol = (Frame*)pkt_data;
	ethernet_type = ntohs(ethernet_protocol->FrameType);
	printf("以太网类型 :\t");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		printf("IPv4\n");
		break;
	case 0x0806:
		printf("ARP\n");
		break;
	case 0x8035:
		printf("RARP\n");
		break;
	default:
		cout << "unknown" << endl;
		break;
	}
	mac_addr = ethernet_protocol->SrcMAC;
	printf("Mac源地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		mac_addr[0],
		mac_addr[1],
		mac_addr[2],
		mac_addr[3],
		mac_addr[4],
		mac_addr[5]
	);
	mac_addr = ethernet_protocol->DesMAC;
	printf("Mac目的地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		mac_addr[0],
		mac_addr[1],
		mac_addr[2],
		mac_addr[3],
		mac_addr[4],
		mac_addr[5]
	);

	IP_Packet_Handle(pkt_head, pkt_data);

}

void IP_Packet_Handle(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	IPHead* IPHeader;
	IPHeader = (IPHead*)(pkt_data + 14);//IP包的内容在原有物理帧后14字节开始
	sockaddr_in source, dest;
	char sourceIP[16], destIP[16];
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), 16);
	strncpy(destIP, inet_ntoa(dest.sin_addr), 16);
	cout << "版本：" << (IPHeader->Ver_HLen >> 4) << endl;
	cout << "IP协议首部长度：" << (IPHeader->Ver_HLen & 0x0f) * 4 << " Bytes" << endl;
	cout << "总长度：" << ntohs(IPHeader->TotalLen) << endl;
	cout << "生存时间：" << IPHeader->TTL << endl;
	cout << "协议号：" << static_cast<int>(IPHeader->Protocol) << endl;
	cout << "协议种类：";
	switch (IPHeader->Protocol)
	{
	case 1:
		printf("ICMP\n");
		break;
	case 2:
		printf("IGMP\n");
		break;
	case 6:
		printf("TCP\n");
		break;
	case 17:
		printf("UDP\n");
		break;
	default:
		break;
	}
	cout << "首部检验和：0x" << hex << ntohs(IPHeader->Checksum) << dec << endl;
	cout << "源地址：" << sourceIP << endl;
	cout << "目的地址：" << destIP << endl;
	cout << "==============" << endl;
}
