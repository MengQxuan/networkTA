#include "pcap.h"
#include <iostream>
#include <WinSock2.h>
#include <bitset>
#include <process.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)


// 将地址转换为16进制字符串类型
string* Byte2Hex(unsigned char bArray[], int bArray_len)
{
    // 初始化一个新的字符串指针，用于存储最终的十六进制字符串
    string* strHex = new string();

    for (int i = 0; i < bArray_len; i++)
    {
        char hex1; // 存储高四位的十六进制字符
        char hex2; // 存储低四位的十六进制字符
        int value = bArray[i]; // 获取当前字节的值

        int S = value / 16; // 高四位
        int Y = value % 16; // 低四位

        // 将高四位转换为对应的十六进制字符
        if (S >= 0 && S <= 9)
            hex1 = (char)(48 + S); // 0-9转换为字符'0'-'9'
        else
            hex1 = (char)(55 + S); // 10-15转换为字符'A'-'F'

        // 将低四位转换为对应的十六进制字符
        if (Y >= 0 && Y <= 9)
            hex2 = (char)(48 + Y);
        else
            hex2 = (char)(55 + Y);

        // 拼接当前字节的十六进制字符串
        // 若不是最后一个字节，则在后面添加分隔符'-'
        if (i != bArray_len - 1) {
            *strHex = *strHex + hex1 + hex2 + "-";
        }
        else
            *strHex = *strHex + hex1 + hex2;
    }
    return strHex; // 返回最终的十六进制字符串指针
}




#pragma pack(1) // 设定字节对齐为1字节，确保结构体按精确字节存储
#define BYTE unsigned char // 定义 BYTE 类型，等价于 unsigned char

// 帧首部
typedef struct FrameHeader_t {
    BYTE DesMAC[6];  // 目的 MAC 地址（6 字节）
    BYTE SrcMAC[6];  // 源 MAC 地址（6 字节）
    WORD FrameType;  // 帧类型（2 字节），例如表示 ARP 类型
} FrameHeader_t;

// ARP 帧
typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader; // 帧首部，包含源 MAC、目的 MAC 和帧类型
    WORD HardwareType;         // 硬件类型（2 字节），表示硬件地址类型
    WORD ProtocolType;         // 协议类型（2 字节），表示协议地址类型
    BYTE HLen;                 // 硬件地址长度（1 字节），通常为 6（MAC 地址长度）
    BYTE PLen;                 // 协议地址长度（1 字节），通常为 4（IPv4 地址长度）
    WORD Operation;            // 操作类型（2 字节），1 为请求，2 为响应
    BYTE SendHa[6];            // 源 MAC 地址（6 字节）
    DWORD SendIP;              // 源 IP 地址（4 字节）
    BYTE RecvHa[6];            // 目的 MAC 地址（6 字节）
    DWORD RecvIP;              // 目的 IP 地址（4 字节）
} ARPFrame_t;



#pragma pack()
ARPFrame_t ARPFrame;//要发送的APR数据包(其他主机）
ARPFrame_t ARPF_Send;//要发送的APR数据包（本机）
unsigned char mac[44], desmac[44];//目的主机和其他主机的mac


void ARP_show(struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct ARPFrame_t* arp;
    arp = (struct ARPFrame_t*)(pkt_data);
    in_addr source, aim;
    memcpy(&source, &arp->SendIP, 4);
    memcpy(&aim, &arp->RecvIP, sizeof(in_addr));
    cout << "源MAC地址：  " << *(Byte2Hex(arp->FrameHeader.SrcMAC, 6)) << endl;
    cout << "源IP地址：   " << inet_ntoa(source) << endl;
    cout << "目的MAC地址：" << *(Byte2Hex(arp->FrameHeader.DesMAC, 6)) << endl;
    cout << "目的IP地址  " << inet_ntoa(aim) << endl;
    cout << endl;
}

//获取本机网络接口的MAC地址和IP地址
void printAddressInfo(const pcap_addr_t* a) {
    char str[INET_ADDRSTRLEN];

    if (a->addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, str, sizeof(str));
        std::cout << "IP地址：" << str << std::endl;

        inet_ntop(AF_INET, &((struct sockaddr_in*)a->netmask)->sin_addr, str, sizeof(str));
        std::cout << "网络掩码：" << str << std::endl;

        inet_ntop(AF_INET, &((struct sockaddr_in*)a->broadaddr)->sin_addr, str, sizeof(str));
        std::cout << "广播地址：" << str << std::endl;
    }
}
//循环打印设备信息
void printInterfaceList(pcap_if_t* alldevs) {
    int n = 1;

    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        std::cout << n++ << "." << std::endl;

        if (d->description)
            std::cout << "(" << d->description << ")" << std::endl << std::endl;
        else
            std::cout << "(No description)\n";

        for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
            printAddressInfo(a);
        }
    }

    if (n == 1) {
        std::cout << "\nNo interfaces found!\n";
    }
}

pcap_if_t* getInterfaceList() {
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs_ex: " << errbuf << std::endl;
        return nullptr;
    }

    return alldevs;
}

void initializeMACAddress(unsigned char* address, unsigned char value) {
    for (int i = 0; i < 6; i++) {
        address[i] = value;
    }
}

void SET_ARP_HOST(ARPFrame_t& ARPFrame1, const char* ip) {
    // 初始化帧头和ARP数据帧的MAC地址
    initializeMACAddress(ARPFrame1.FrameHeader.DesMAC, 0x00); // 目的 MAC 地址全 0
    initializeMACAddress(ARPFrame1.FrameHeader.SrcMAC, 0x1f); // 本机 MAC 地址设为 0x1f
    initializeMACAddress(ARPFrame1.SendHa, 0x1f);             // 源 MAC 地址设为 0x1f
    initializeMACAddress(ARPFrame1.RecvHa, 0x00);             // 目标 MAC 地址全 0

    // 设置以太网和 ARP 协议的基本字段
    ARPFrame1.FrameHeader.FrameType = htons(0x0806);         // 帧类型设为 ARP（0x0806）
    ARPFrame1.HardwareType = htons(0x0001);                  // 硬件类型设为以太网（0x0001）
    ARPFrame1.ProtocolType = htons(0x0800);                  // 协议类型设为 IPv4（0x0800）
    ARPFrame1.HLen = 6;                                      // 硬件地址长度为 6 字节
    ARPFrame1.PLen = 4;                                      // 协议地址长度为 4 字节
    ARPFrame1.Operation = htons(0x0001);                     // 操作类型设为请求（0x0001）
    ARPFrame1.SendIP = inet_addr("192.168.120.110");         // 设置源 IP 地址（本地 IP）
    ARPFrame1.RecvIP = inet_addr(ip);                        // 设置目标 IP 地址（参数传入的IP）
}

void SET_ARP_DEST(ARPFrame_t& ARPFrame, const char* ip, const unsigned char* mac) {
    // 初始化目标帧的 MAC 地址
    initializeMACAddress(ARPFrame.FrameHeader.DesMAC, 0xff); // 广播 MAC 地址（目的 MAC）
    initializeMACAddress(ARPFrame.RecvHa, 0x00);             // 接收方 MAC 地址设为 0
    memcpy(ARPFrame.FrameHeader.SrcMAC, mac, 6);             // 使用本地网卡 MAC 作为源 MAC
    memcpy(ARPFrame.SendHa, mac, 6);                         // 源 MAC 地址也设为本地网卡 MAC

    // 设置以太网帧和 ARP 协议的基本字段
    ARPFrame.FrameHeader.FrameType = htons(0x0806);          // 帧类型设为 ARP
    ARPFrame.HardwareType = htons(0x0001);                   // 硬件类型设为以太网
    ARPFrame.ProtocolType = htons(0x0800);                   // 协议类型设为 IPv4
    ARPFrame.HLen = 6;                                       // 硬件地址长度为 6 字节
    ARPFrame.PLen = 4;                                       // 协议地址长度为 4 字节
    ARPFrame.Operation = htons(0x0001);                      // 操作类型设为请求
    ARPFrame.SendIP = inet_addr(ip);                         // 设置源 IP 地址（传入的参数IP）
}




int main() {

    pcap_if_t* alldevs = getInterfaceList();//指向设备链表首部的指针
    pcap_if_t* d;
    pcap_addr_t* a;
    if (alldevs != NULL) {

        printInterfaceList(alldevs);
    }
    char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区

    cout << endl << endl;

    //设备链表首部的指针
    d = alldevs;

    int j;
    cout << "请选择发送数据包的网卡：";
    cin >> j;
    int i = 0;
    //获取指向选择发送数据包网卡的指针

    while (i < j - 1) {
        i++;
        d = d->next;
    }


    //打开用户选择设备的网卡
    pcap_t* dev = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);


    //保存网卡的ip地址（指向缓冲区的指针，用于存储 IP 地址的 NULL 终止字符串表示形式。）
    char ip[INET_ADDRSTRLEN];


    for (a = d->addresses; a != NULL; a = a->next) {
        //判断该地址是否为IP地址
        if (a->addr->sa_family == AF_INET) {
            //二进制IP地址转换为文本形式的IP地址
            inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, ip, sizeof(ip));
        }
    }
    cout << ip;
    cout << endl << d->description << endl;

    //获取本机的MAC地址

    //设置ARP帧相关
    SET_ARP_HOST(ARPF_Send, ip);

    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    struct pcap_pkthdr* header = new pcap_pkthdr;
    int k;
    //发送构造好的数据包
    
    while ((k = pcap_next_ex(dev, &pkt_header, &pkt_data)) >= 0) { // 循环获取数据包
        // 发送ARP请求数据包
        pcap_sendpacket(dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));

        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data); // 将接收到的数据包转为ARP帧结构
        if (k == 1) { // 如果成功读取到数据包

            // 检查是否为ARP响应包（以太网帧类型0x0806表示ARP，操作类型0x0002表示ARP响应）
            if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002)) {
                cout << "ARP数据包：\n";
                ARP_show(header, pkt_data); // 打印ARP包的源和目标信息
                memcpy(mac, &(pkt_data[22]), 6); // 从数据包中提取目标主机的MAC地址
                cout << "本机MAC：" << *(Byte2Hex(mac, 6)) << endl; // 打印本机MAC地址
                break; // 接收到ARP响应后退出循环
            }
        }
    }


    if (k < 0) {
        cout << "Error in pcap_next_ex." << endl;
    }
    cout << endl;

    //设置ARP帧

    SET_ARP_DEST(ARPFrame, ip, mac);

    cout << "请输入目的主机的IP地址：";
    char desip[INET_ADDRSTRLEN];
    cin >> desip;
    ARPFrame.RecvIP = inet_addr(desip); //设置为请求的IP地址

    while ((k = pcap_next_ex(dev, &pkt_header, &pkt_data)) >= 0) { // 不断捕获数据包

        pcap_sendpacket(dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t)); // 发送ARP请求包
        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data); // 将接收到的数据包转换为ARP帧结构
        if (k == 0) continue; // 若无数据包则继续循环

        else // 若捕获到数据包则检查是否符合ARP响应包格式
            // 验证包类型是否为ARP响应包，且接收IP地址是否与目标一致
            if (arp_message->FrameHeader.FrameType == htons(0x0806)
                && arp_message->Operation == htons(0x0002)
                && *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP) {

                cout << "ARP数据包：\n";
                ARP_show(header, pkt_data); // 打印ARP包中的源和目的信息
                memcpy(desmac, &(pkt_data[22]), 6); // 提取目标主机的MAC地址
                cout << "目的主机的MAC：" << *(Byte2Hex(desmac, 6)) << endl; // 打印目标主机的MAC地址
                break; // 成功接收响应包后退出循环
            }
    }

    pcap_freealldevs(alldevs);
    system("pause");
}