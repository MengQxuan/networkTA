#pragma once
#include <iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "winsock2.h"
#include "stdio.h"
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996) // 要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define RT_TABLE_SIZE 256 // 路由表大小
using namespace std;
#pragma pack(1) // 以1byte方式对齐

// 路由表结构
typedef struct router_table
{
    ULONG netmask; // 网络掩码
    ULONG desnet;  // 目的网络
    ULONG nexthop; // 下一站路由
} router_table;

// 数据帧首部
typedef struct FrameHeader_t
{
    BYTE DesMac[6]; // 目的mac地址，6字节
    BYTE SrcMac[6]; // 源mac地址，6字节
    WORD FrameType; // 帧类型，指示帧的协议类型
} FrameHeader_t;

// IP数据包的首部
typedef struct IPHeader_t
{
    BYTE Ver_HLen;     // 版本与首部长度
    BYTE TOS;          // 服务类型
    WORD TotalLen;     // 整个IP数据包的总长度
    WORD ID;           // 标识
    WORD Flag_Segment; // 标志和偏移（分段信息）
    BYTE TTL;          // 生存周期，数据包在网络中可以跳跃的最大次数
    BYTE Protocol;     // 协议类型
    WORD Checksum;     // 校验和
    ULONG SrcIP;       // 源IP地址
    ULONG DstIP;       // 目的IP地址
} IPHeader_t;

// 包含帧首部和IP首部的数据包
typedef struct IPData_t
{
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
} IPData_t;

// ARP帧
typedef struct ARPFrame_t
{
    FrameHeader_t FrameHeader; // 帧首部
    WORD HardwareType;         // 硬件类型
    WORD ProtocolType;         // 协议类型
    BYTE HLen;                 // 硬件地址长度
    BYTE PLen;                 // 协议地址长度
    WORD Operation;            // 操作类型（请求或响应）
    BYTE SendHa[6];            // 发送方MAC地址
    DWORD SendIP;              // 发送方IP地址
    BYTE RecvHa[6];            // 接收方MAC地址
    DWORD RecvIP;              // 接收方IP地址
} ARPFrame_t;

#pragma pack() // 恢复对齐方式

// 选路 实现最长匹配
// 确保了选择的路由条目是最具体的，从而提高了路由的准确性和效率
ULONG search(router_table *t, int tLength, ULONG DesIP) // 返回下一跳步的IP
{
    ULONG best_desnet = 0;            // 最优匹配的目的网络
    int best = -1;                    // 最优匹配路由表项的下标
    for (int i = 0; i < tLength; i++) // 遍历路由表t
    {
        if ((t[i].netmask & DesIP) == t[i].desnet) // 检查目标IP地址与网络掩码的按位与结果是否等于目的网络desnet
        {
            if (t[i].desnet >= best_desnet) // 最长匹配
            {
                best_desnet = t[i].desnet; // 保存最优匹配的目的网络
                best = i;                  // 更新最优匹配路由表项的下标
            }
        }
    }
    if (best == -1)
        return 0xffffffff; // 没有匹配项
    else
        return t[best].nexthop; // 获得匹配项
}

// 向路由表中添加项（没有做插入时排序的优化）
bool additem(router_table *t, int &tLength, router_table item)
{
    if (tLength == RT_TABLE_SIZE) // 路由表满则不能添加
        return false;
    for (int i = 0; i < tLength; i++)
        if ((t[i].desnet == item.desnet) && (t[i].netmask == item.netmask) && (t[i].nexthop == item.nexthop))
            return false; // 路由表中已存在该项，则不能添加
    t[tLength] = item;    // 添加到表尾
    tLength = tLength + 1;
    return true;
}

// 从路由表中删除项
bool deleteitem(router_table *t, int &tLength, int index)
{
    if (tLength == 0) // 路由表空则不能删除
        return false;
    for (int i = 0; i < tLength; i++)
        if (i == index) // 当前索引等于目标索引，删除表项
        {
            for (; i < tLength - 1; i++)
                t[i] = t[i + 1];
            tLength = tLength - 1;
            return true;
        }
    return false; // 路由表中不存在该项则不能删除
}

// 打印IP
void printIP(ULONG IP)
{
    BYTE *p = (BYTE *)&IP;
    for (int i = 0; i < 3; i++)
    {
        cout << dec << (int)*p << ".";
        p++;
    }
    cout << dec << (int)*p << " ";
}

void printMAC(BYTE MAC[]) // 打印mac
{
    for (int i = 0; i < 5; i++)
        printf("%02X-", MAC[i]);
    printf("%02X\n", MAC[5]);
}
// 打印路由表
void print_rt(router_table *t, int &tLength)
{
    for (int i = 0; i < tLength; i++)
    {
        cout << "\t网络掩码\t"
             << "目的网络\t"
             << "下一站路由\t" << endl;
        cout << i << "    ";
        printIP(t[i].netmask);
        cout << "    ";
        printIP(t[i].desnet);
        cout << "       ";
        printIP(t[i].nexthop);
        cout << endl;
    }
}

void setchecksum(IPData_t *temp) // 设置校验和
{
    temp->IPHeader.Checksum = 0;
    unsigned int sum = 0;
    WORD *t = (WORD *)&temp->IPHeader; // 每16位为一组
    for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
    {
        sum += t[i];           // 累加当前16位整数到sum
        while (sum >= 0x10000) // 如果溢出，则进行回卷
        {
            int s = sum >> 16;
            sum -= 0x10000;
            sum += s;
        }
    }
    temp->IPHeader.Checksum = ~sum; // 结果取反
}

bool checkchecksum(IPData_t *temp) // 检验
{
    unsigned int sum = 0;
    WORD *t = (WORD *)&temp->IPHeader;
    for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
    {
        sum += t[i];
        while (sum >= 0x10000) // 包含原有校验和一起进行相加
        {
            int s = sum >> 16;
            sum -= 0x10000;
            sum += s;
        }
    }
    // 65535：1111 1111 1111 1111
    if (sum == 65535) // 源码+反码-》全1
        return 1;     // 校验和正确
    return 0;
}