#include "router.h"
int main()
{
    int number = 0;
    bool flag = 0; // 标志位，表示是否得到IPv4包，0为没有得到。
    BYTE my_mac[6];
    BYTE its_mac[6];
    ULONG my_ip;

    router_table *rt = new router_table[RT_TABLE_SIZE]; // 把路由表项用链表串联起来
    int rt_length = 0;                                  // 路由表的初始长度

    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *a;

    ULONG targetIP;

    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本机网卡信息
    int num = 0; // 记录有几个网络接口卡
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
                            NULL,
                            &alldevs,
                            errbuf) == -1)
    {
        cout << "have errors" << endl;
    }

    for (d = alldevs; d != NULL; d = d->next)
    {
        cout << num + 1 << ": ";
        cout << "NAME: " << d->name << endl;               // 输出网络接口卡设备的名字
        cout << "DESCRIPTION: " << d->description << endl; // 获取该网络接口卡设备的描述信息
        num++;

        for (a = d->addresses; a != NULL; a = a->next)
        {
            if (a->addr->sa_family == AF_INET)
            {
                cout << "IP地址：";
                printIP((((sockaddr_in *)a->addr)->sin_addr).s_addr);
                cout << "子网掩码：";
                printIP((((sockaddr_in *)a->netmask)->sin_addr).s_addr);
                cout << "广播地址：";
                printIP((((sockaddr_in *)a->broadaddr)->sin_addr).s_addr);
                cout << endl
                     << endl;
            }
        }
    }
    cout << "共有" << num << "个网络接口卡" << endl;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // 打开网卡获取IP
    cout << "打开第几个网络接口卡？" << endl;
    int in;
    cin >> in;
    in--;
    int i = 0;
    for (d = alldevs; d != NULL && i != in; d = d->next)
    {
        i++;
    }
    // 打印选择网卡的IP、子网掩码、广播地址
    for (a = d->addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            cout << "IP地址：";
            printIP((((sockaddr_in *)a->addr)->sin_addr).s_addr);
            cout << "子网掩码：";
            printIP((((sockaddr_in *)a->netmask)->sin_addr).s_addr);
            cout << "广播地址：";
            printIP((((sockaddr_in *)a->broadaddr)->sin_addr).s_addr);
            cout << endl;

            ULONG NetMask, DesNet, NextHop;
            DesNet = (((sockaddr_in *)a->addr)->sin_addr).s_addr;
            NetMask = (((sockaddr_in *)a->netmask)->sin_addr).s_addr;
            DesNet = DesNet & NetMask;
            NextHop = 0;
            router_table temp;
            temp.netmask = NetMask;
            temp.desnet = DesNet;
            temp.nexthop = NextHop;
            additem(rt, rt_length, temp); // 本机信息作为默认路由
        }
    }

    char errbuf1[PCAP_ERRBUF_SIZE];
    pcap_t *p; // 记录调用pcap_open()的返回值，即句柄。

    p = pcap_open(d->name, 1500, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf1); // 打开网络接口

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // 增加或删除路由表项
    ULONG NetMask, DesNet, NextHop;
    char *netmask = new char[20];
    char *desnet = new char[20];
    char *nexthop = new char[20];
    bool stop = 1; // stop=0时，停止修改路由表
    cout << "你想要改变路由表吗? y or n" << endl;
    char ch1;
    cin >> ch1;
    if (ch1 == 'n')
    {
        stop = 0;
        cout << "路由表:" << endl;
        print_rt(rt, rt_length);
    }
    while (stop)
    {
        cout << "添加还是删除? a or d" << endl;
        string str;
        cin >> str;

        if (str == "a")
        {
            cout << "请输入路由表，输入顺序为：目的网络号，子网掩码，下一跳步" << endl;
            cin >> desnet;
            cin >> netmask;
            cin >> nexthop;
            DesNet = inet_addr(desnet);
            NetMask = inet_addr(netmask);
            NextHop = inet_addr(nexthop);

            router_table temp;
            temp.netmask = NetMask;
            temp.desnet = DesNet;
            temp.nexthop = NextHop;

            additem(rt, rt_length, temp);

            char ch;
            cout << "继续添加?  y or n" << endl;
            print_rt(rt, rt_length); // 打印路由表
            cin >> ch;
            if (ch == 'n')
            {
                stop = 0;
                cout << "路由表:" << endl;
                print_rt(rt, rt_length);
                break;
            }
        }
        else if (str == "d")
        {
            int index;
            cout << "请输入要删除的表项索引（从零开始）" << endl;
            cin >> index; // 从下标0开始
            deleteitem(rt, rt_length, index);
            char ch;
            cout << "继续删除?  y or n" << endl;
            cin >> ch;
            if (ch == 'n')
            {
                stop = 0;
                cout << "路由表:" << endl;
                print_rt(rt, rt_length);
                break;
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // 过滤，只要ARP和IP包
    u_int net_mask;
    char packet_filter[] = "ip or arp";
    struct bpf_program fcode;
    net_mask = ((sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    if (pcap_compile(p, &fcode, packet_filter, 1, net_mask) < 0)
    {
        printf("无法编译包过滤器。请检查语法！\n");
        pcap_freealldevs(alldevs);
        return 0;
    }
    if (pcap_setfilter(p, &fcode) < 0)
    {
        printf("过滤器设置错误\n");
        pcap_freealldevs(alldevs);
        return 0;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // 向自己发送arp包，获取本机的MAC
    BYTE scrMAC[6];
    ULONG scrIP;
    for (i = 0; i < 6; i++)
    {
        scrMAC[i] = 0x66;
    }
    scrIP = inet_addr("112.112.112.112"); // 虚拟IP

    for (d = alldevs, i = 0; i < in; i++, d = d->next)
        ;
    for (a = d->addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            targetIP = inet_addr(inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
            my_ip = targetIP;
        }
    }

    ARPFrame_t ARPFrame;
    for (int i = 0; i < 6; i++)
    {
        ARPFrame.FrameHeader.DesMac[i] = 0xff;
        ARPFrame.FrameHeader.SrcMac[i] = scrMAC[i];
        ARPFrame.SendHa[i] = scrMAC[i];
        ARPFrame.RecvHa[i] = 0;
    }
    ARPFrame.FrameHeader.FrameType = htons(0x0806);
    ARPFrame.HardwareType = htons(0x0001);
    ARPFrame.ProtocolType = htons(0x0800);
    ARPFrame.HLen = 6;
    ARPFrame.PLen = 4;
    ARPFrame.Operation = htons(0x0001);
    ARPFrame.SendIP = scrIP;
    ARPFrame.RecvIP = targetIP;
    int ret_send = pcap_sendpacket(p, (u_char *)&ARPFrame, sizeof(ARPFrame_t));

    // 要默认发包成功  不然会出错
    /*if (ret_send)
    {
        cout << "向自己发包失败" << endl;
    }*/
    // else
    //{
    cout << "向自己发包成功" << endl;

    // 截获自己的MAC
    pcap_pkthdr *pkt_header1 = new pcap_pkthdr[1500];
    const u_char *pkt_data1;
    int res;
    ARPFrame_t *ARPFrame1;

    while (!flag)
    {
        res = pcap_next_ex(p, &pkt_header1, &pkt_data1);
        if ((res == 0))
        {
            continue;
        }
        if (res == 1)
        {
            ARPFrame1 = (ARPFrame_t *)pkt_data1;
            if (ARPFrame1->SendIP == targetIP && ARPFrame1->RecvIP == scrIP)
            {
                cout << "本机IP:";
                printIP(ARPFrame1->SendIP);
                cout << endl;

                cout << "本机MAC:";
                for (int i = 0; i < 6; i++)
                {
                    my_mac[i] = ARPFrame1->SendHa[i];
                    cout << hex << (int)my_mac[i];
                    if (i != 5)
                        cout << "-";
                    else
                        cout << endl;
                }
                flag = 1;
            }
        }
    }
    //}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // 获取目的mac为本机mac，目的ip非本机ip的ip数据报
    ULONG nextIP; // 路由表中下一跳的IP地址
    flag = 0;     // 是否得到数据包，0为没有得到。

    IPData_t *IPPacket;

    pcap_pkthdr *pkt_header = new pcap_pkthdr[1500];
    const u_char *pkt_data;
    // 不断收包
    while (1)
    {
        // 数据包的获取
        int ret_pcap_next_ex;
        ret_pcap_next_ex = pcap_next_ex(p, &pkt_header, &pkt_data); // 在打开的网络接口卡上获取网络数据包
        if (ret_pcap_next_ex)
        {
            // cout << "数据包的长度len=" << pkt_header->len << endl;
            WORD RecvChecksum;
            WORD FrameType;

            IPPacket = (IPData_t *)pkt_data;

            ULONG Len = pkt_header->len + sizeof(FrameHeader_t); // 数据包大小包括帧数据部分长度和帧首部长度
            u_char *sendAllPacket = new u_char[Len];
            for (i = 0; i < Len; i++)
            {
                sendAllPacket[i] = pkt_data[i];
            }

            RecvChecksum = IPPacket->IPHeader.Checksum;
            IPPacket->IPHeader.Checksum = 0;
            FrameType = IPPacket->FrameHeader.FrameType;
            bool desmac_equal = 1; // 目的mac地址与本机mac地址是否相同，相同为1；
            for (int i = 0; i < 6; i++)
            {
                if (my_mac[i] != IPPacket->FrameHeader.DesMac[i])
                {
                    desmac_equal = 0;
                }
            }
            bool desIP_equal = 0; // 目的IP与本机IP是否相同，不相同为1；
            if (IPPacket->IPHeader.DstIP != my_ip)
            {
                desIP_equal = 1;
                targetIP = IPPacket->IPHeader.DstIP;
            }
            bool Is_ipv4 = 0;
            if (FrameType == 0x0008)
            {
                Is_ipv4 = 1;
            }
            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (Is_ipv4 && desmac_equal && desIP_equal) // 处理目的MAC为本机MAC，目的IP不是本机IP的IPv4包
            {
                cout << "\n正为该包进行转发" << endl;

                int version = (IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4;
                int headlen = (IPPacket->IPHeader.Ver_HLen & 0x0f);
                int tos = IPPacket->IPHeader.TOS; // 服务类型

                int totallen = ntohs(IPPacket->IPHeader.TotalLen); // 数据包总长度

                int id = ntohs(IPPacket->IPHeader.ID); // 标识
                //	int flag_segment = (ntohs(IPPacket->IPHeader.Flag_segment) & 0xe000) >> 13;
                //	int offset = (ntohs(IPPacket->IPHeader.Flag_segment) & 0x1fff);
                int ttl = IPPacket->IPHeader.TTL;
                int protocol = IPPacket->IPHeader.Protocol;

                cout << "version=" << version << endl;
                cout << "headlen=" << headlen << endl;
                cout << "tos=" << dec << tos << endl;
                cout << "totallen=" << dec << totallen << endl;
                cout << "id="
                     << "0x" << id << endl;
                cout << "ttl=" << dec << ttl << endl;
                cout << "protocol=" << dec << protocol << endl;

                cout << "数据包源地址：";
                printIP(IPPacket->IPHeader.SrcIP);
                cout << endl;
                cout << "数据包目的地址：";
                printIP(IPPacket->IPHeader.DstIP);
                cout << endl;

                // 选路投递
                nextIP = search(rt, rt_length, IPPacket->IPHeader.DstIP);
                cout << "路由表长度为：" << rt_length << endl;
                cout << "nextIP:";
                printIP(nextIP);
                cout << endl;
                if (nextIP == 0)
                {
                    nextIP = IPPacket->IPHeader.DstIP; // 找不到合适的路由，则直接将目的IP设置为下一跳
                }
                else if (nextIP == 0xffffffff)
                {
                    cout << "出错，将抛弃该包" << endl;
                }

                flag = 1;

                ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                // 向nextIP发ARP请求，获取下一跳的MAC地址
                for (i = 0; i < 6; i++)
                {
                    scrMAC[i] = my_mac[i];
                }
                scrIP = my_ip;

                targetIP = nextIP;

                // 组装ARP包
                for (int i = 0; i < 6; i++)
                {
                    ARPFrame.FrameHeader.DesMac[i] = 0xff;
                    ARPFrame.FrameHeader.SrcMac[i] = scrMAC[i];
                    ARPFrame.SendHa[i] = scrMAC[i];
                    ARPFrame.RecvHa[i] = 0;
                }
                ARPFrame.FrameHeader.FrameType = htons(0x0806);
                ARPFrame.HardwareType = htons(0x0001);
                ARPFrame.ProtocolType = htons(0x0800);
                ARPFrame.HLen = 6;
                ARPFrame.PLen = 4;
                ARPFrame.Operation = htons(0x0001);
                ARPFrame.SendIP = scrIP;
                cout << "sendIP:";
                printIP(ARPFrame.SendIP);
                cout << endl;
                ARPFrame.RecvIP = targetIP;
                cout << "recvIP:";
                printIP(ARPFrame.RecvIP);
                cout << endl;
                int send_ret = pcap_sendpacket(p, (u_char *)&ARPFrame, sizeof(ARPFrame_t));

                /*if (send_ret)
                {
                    cout << "发包失败" << endl;
                }*/
                // else
                //{
                cout << "发包成功" << endl;

                // 截获它的MAC
                pcap_pkthdr *pkt_header2 = new pcap_pkthdr[1500];
                const u_char *pkt_data2;

                int res;
                ARPFrame_t *ARPFrame2;

                int flag1 = 0;
                while (!flag1)
                {
                    res = pcap_next_ex(p, &pkt_header2, &pkt_data2);

                    if ((res == 0))
                    {
                        continue;
                    }
                    if (res == 1)
                    {
                        ARPFrame2 = (ARPFrame_t *)pkt_data2;

                        if (ARPFrame2->SendIP == nextIP && ARPFrame2->RecvIP == my_ip)
                        {
                            cout << "NextIP的MAC地址:";
                            for (int i = 0; i < 6; i++)
                            {
                                its_mac[i] = ARPFrame2->FrameHeader.SrcMac[i];
                                cout << hex << (int)its_mac[i];
                                if (i != 5)
                                    cout << "-";
                                else
                                    cout << endl;
                            }
                            flag1 = 1;
                            cout << "NextIP的IP:";
                            printIP(ARPFrame2->SendIP);
                            cout << endl;
                        }
                    }
                }
                //}

                ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                // 到目前为止知道了：自己的IP:my_IP;自己的MAC：my_mac[6]；要转发的目的IP:targetIP;要转发的目的MAC:its_mac[6] 可以向下一跳发送报文了
                // 转发包
                IPData_t *TempIP;
                TempIP = (IPData_t *)sendAllPacket;
                // TempIP->IPHeader.TTL -= 1;//TTL-1 只要改TTL就出错？
                for (int t = 0; t < 6; t++)
                {
                    TempIP->FrameHeader.DesMac[t] = its_mac[t]; // 目的mac地址换为下一跳步的ip地址对应的mac地址，其他不变。
                    TempIP->FrameHeader.SrcMac[t] = my_mac[t];
                }
                if (!pcap_sendpacket(p, sendAllPacket, Len)) // 将修改后的数据包转发出去
                {
                    cout << "转发成功" << endl;
                    IPData_t *t;
                    t = (IPData_t *)sendAllPacket;
                    cout << "源IP地址：";
                    printIP(t->IPHeader.SrcIP);
                    cout << "\t";

                    cout << "目的IP地址：";
                    printIP(t->IPHeader.DstIP);
                    cout << endl;

                    cout << "目的mac：";
                    for (int i = 0; i < 6; i++)
                    {
                        cout << hex << (int)t->FrameHeader.DesMac[i];
                        if (i != 5)
                            cout << "-";
                    }
                    cout << "\t";
                    cout << "源mac：";
                    for (i = 0; i < 6; i++)
                    {
                        cout << hex << (int)t->FrameHeader.SrcMac[i];
                        if (i != 5)
                            cout << "-";
                    }
                    cout << endl;
                }
            }
        }
    }
    cout << "End" << endl;
    pcap_freealldevs(alldevs); // 释放设备列表
    return 0;
}

