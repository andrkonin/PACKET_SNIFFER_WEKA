
#include <QtGui>
#include <QColor>

#include "sniffer.h"

SNIFFER::SNIFFER()
{
   // time=new QTime();
    //datetime=new QDateTime();
    //time=new QTime();
    //time->start();
    QFont font("Courier", 8, QFont::Normal);
    QFont font1("Courier",8,QFont::Bold);
    setWindowTitle(tr("Sniffer"));
    //resize(500, 400);
    interface=false;

    status=new QTextEdit();
    status->setWordWrapMode(QTextOption::NoWrap);
    status->setFont(font);
    status->setFixedSize(700,200);
    status->setReadOnly(true);
    setCentralWidget(status);
    pcnt=0;
    error=false;

    sipC=0;
    dipC=0;
    protC=0;
    lenC=0;
    sCC=0;
    dCC=0;
    // open();
    //emit(onLoad());

}


void SNIFFER::open(char *INAME)
{   
    pcnt=0;
    if (!wekaview)
    {
        status->append("********************************************************************************************************");
        sprintf(txtstr,"Try to use interface %s:",INAME);
        status->append(txtstr);
    }
    gi=GeoIP_new(GEOIP_STANDARD);
   

    /* CHECKING ALL ACCESSIBLE INTERFACES

    pcap_if_t *alldevsp;

    if (pcap_findalldevs(&alldevsp,errbuf)<0)
    {
        status->append(errbuf);
    }
    while (alldevsp!=NULL)
    {
        status->append(alldevsp->name);
        alldevsp=alldevsp->next;
    }
    */

    /* FIRST WORKABLE INTERFACE

    dev=pcap_lookupdev(errbuf);
    if (dev==NULL)
    {
        status->append("ERROR:Couldn't find default device:");
        status->append(errbuf);
    }
    else
    {
        status->append("Interface chosen:");
        status->append(dev);
    }
    */
    //filter_exp="port 80";

    /* Workable version */

    filter_exp="";
    // "udp" "tcp" "icmp"

    //dev=pcap_lookupdev(errbuf);
    dev=INAME;
    if (dev==NULL)
    {
        status->append("Coulnd't find default device or there are no suitable devices.");
        status->append(errbuf);
        interface=false;
        return ;
    }

    if (!wekaview)
        status->append(dev);

    if (pcap_lookupnet(dev,&net,&mask,errbuf)==-1)
    {
        status->append("Couldn't get netmask for device");
        status->append(dev);
        status->append(errbuf);
        net=0;
        mask=0;
    }
    handle=pcap_open_live(dev,SNAP_LEN,1,1000,errbuf);
    if (handle==NULL)
    {
        status->append("Coulnd't open device");
        interface=false;
        return ;
    }
    else
        if (!wekaview)
            status->append("Device found");
    if (pcap_compile(handle,&fp,filter_exp,0,net)==-1)
    {
        status->append("Couldn't parse filter");
        status->append(filter_exp);
        status->append(pcap_geterr(handle));
        interface=false;
        return ;
    }
    if (pcap_setfilter(handle,&fp)==-1)
    {
        status->append("Couldn't install filter");
        interface=false;
        return ;
    }
    else
    {
        if (!wekaview)
        {
            sprintf(txtstr,"Filter set: '%s'",filter_exp);
            status->append(txtstr);
        }
    }
    interface=true;
    if (!wekaview)
    {
        status->append("--------------------------------------------------------------------------------------------------------");
        status->append("Num    From:          To:             Len      Protocol   Time              Src.Country   Dst.Country");
        status->append("--------------------------------------------------------------------------------------------------------");
    //packet=pcap_next(handle,&header);
    }

    //status->append(QString::number(header.len,10));
    //pcap_close(handle);

    result="Processing ...";
    emit onLoad();

}

void SNIFFER::update()
{
    if (interface)
    {

        //pcap_loop(handle, num_packets, got_packet, NULL);

        if (packet=pcap_next(handle,&header))
        {

            got_packet(0,&header,packet);

        }

    }
}

void SNIFFER::close()
{
    //str=QString::number(pcnt,10)+" packets captured.";

    if (interface)
    {
        pcap_freecode(&fp);
        pcap_close(handle);
        interface=false;
        sprintf(txtstr,"%d packets captured. Capture complete.",pcnt);
        //printf("\nCapture complete.\n");
        pcnt=0;
        if (!wekaview)
            status->append(txtstr);
        result=txtstr;
        emit onLoad();
    }
}

void SNIFFER::clear()
{
    status->clear();
    sipC=0;
    dipC=0;
    protC=0;
    lenC=0;
    sCC=0;
    dCC=0;
}

void SNIFFER::save(QString fileName)
{
    //status->append(fileName);
    QFile file(fileName);
    file.open(QFile::WriteOnly);
    QTextStream out(&file);
    out << status->toPlainText() << endl;
    file.close();
}

void SNIFFER::saveweka(QString fileName)
{
    QFile file(fileName);
    file.open(QFile::WriteOnly);
    QTextStream out(&file);
    int i;
    out << "@relation traffic " << endl;

    out << "@attribute srcIP {";
    if (sipC!=0)
    {
        //out << sipC << endl;

        for (i=0;i<sipC-1;i++)
        {
            //printf("%d - %s\n ",i,srcipARR[i]);
            out << srcipARR[i] << ",";
        }
        out << srcipARR[sipC-1];
    }
    out << "}" << endl;

    out << "@attribute dstIP {";
    if (dipC!=0)
    {
        for (i=0;i<dipC-1;i++)
        {
            out << dstipARR[i] << ",";
        }
        out << dstipARR[dipC-1];
    }
    out << "}" << endl;

    out << "@attribute length {";
    if (lenC!=0)
    {
        for (i=0;i<lenC-1;i++)
        {
            out << lenARR[i] << ",";
        }
        out << lenARR[lenC-1];
    }
    out << "}" << endl;

    out << "@attribute protocol {";
    if (protC!=0)
    {
        for (i=0;i<protC-1;i++)
        {
            out << protARR[i] << ",";
        }
        out << protARR[protC-1];
    }
    out << "}" << endl;

    out << "@attribute srcCountry {";
    if (sCC!=0)
    {
        for (i=0;i<sCC-1;i++)
        {
            out << srcCARR[i] << ",";
        }
        out << srcCARR[sCC-1];
    }
    out << "}" << endl;

    out << "@attribute dstCountry {";
    if (dCC!=0)
    {
        for (i=0;i<dCC-1;i++)
        {
            out << dstCARR[i] << ",";
        }
        out << dstCARR[dCC-1];
    }
    out << "}" << endl;

    out << "@attribute Month {";
    for (i=1;i<12;i++)
    {
        out << i << ',';
    }
    out << 12;
    out << "}" << endl;

    out << "@attribute MonthDay {";
    for (i=1;i<31;i++)
    {
        out << i << ',';
    }
    out << 31;
    out << "}" << endl;

    out << "@attribute WeekDay {";
    out << "Monday" << ",";
    out << "Tuesday" << ",";
    out << "Wensday" << ",";
    out << "Thursday" << ",";
    out << "Friday" << ",";
    out << "Saturday" << ",";
    out << "Sunday";
    out << "}" << endl;

    out << "@attribute Hour {";
    for (i=0;i<23;i++)
    {
        out << i << ',';
    }
    out << 23;
    out << "}" << endl;

    out << "@attribute Minute {";
    for (i=0;i<59;i++)
    {
        out << i << ',';
    }
    out << 59;
    out << "}" << endl;

    out << "@attribute Second {";
    for (i=0;i<59;i++)
    {
        out << i << ',';
    }
    out << 59;
    out << "}" << endl;

    out << "@attribute Millisecond {";
    for (i=0;i<999;i++)
    {
        out << i << ',';
    }
    out << 999;
    out << "}" << endl;

    out << "@attribute AMPM {am,pm";
    out << "}" << endl;

    out << "@attribute DayNightEvening {day,night,evening";
    out << "}" << endl;

    out << "@data" << endl;
    out << status->toPlainText() << endl;
    file.close();
}

void
SNIFFER::print_hex_ascii_line(const u_char *payload, int len, int offset)
{

        int i;
        int gap;
        const u_char *ch;

        sprintf(txtstr,"%05d   ", offset);
        str=txtstr;

        ch = payload;
        for(i = 0; i < len; i++) {
                sprintf(txtstr,"%02x ", *ch);
                str+=txtstr;
                ch++;

                if (i == 7)
                    {
                        sprintf(txtstr," ");
                        str+=txtstr;
                        // status->append(txtstr);
                    }
        }
        if (len < 8)
        {
                sprintf(txtstr," ");
                str+=txtstr;
                //status->append(txtstr);
            }

        if (len < 16) {
                gap = 16 - len;
                for (i = 0; i < gap; i++) {
                        sprintf(txtstr,"   ");
                        str+=txtstr;
                        //status->append(txtstr);
                }
        }
        sprintf(txtstr,"   ");
        str+=txtstr;
        //status->append(txtstr);

        ch = payload;
        for(i = 0; i < len; i++) {
                if (isprint(*ch))
            {
                        sprintf(txtstr,"%c", *ch);
                        str+=txtstr;
                        //status->append(txtstr);
                    }
                else
                {
                        sprintf(txtstr,".");
                        str+=txtstr;
                        //status->append(txtstr);
                    }
                ch++;
        }

        //printf("\n");
        status->append(str);
return;
}

void
SNIFFER::print_payload(const u_char *payload, int len)
{

        int len_rem = len;
        int line_width = 16;
        int line_len;
        int offset = 0;
        const u_char *ch = payload;

        if (len <= 0)
                return;

        if (len <= line_width) {
                print_hex_ascii_line(ch, len, offset);
                return;
        }

        for ( ;; ) {
                line_len = line_width % len_rem;
                print_hex_ascii_line(ch, line_len, offset);
                len_rem = len_rem - line_len;
                ch = ch + line_len;
                offset = offset + line_width;\
                if (len_rem <= line_width) {
                        print_hex_ascii_line(ch, len_rem, offset);
                        break;
                }
        }
return;
}

void
SNIFFER::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

       // static int count = 1;

        const struct sniff_ethernet *ethernet;
        const struct sniff_ip *ip;
        const struct sniff_tcp *tcp;
        const u_char *payload;

        int size_ip;
        int size_tcp;
        int size_payload;

        pcnt++;
        ethernet = (struct sniff_ethernet*)(packet);

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (!wekaview)
        {
            sprintf(txtstr," %d ", pcnt);

            str=txtstr;
            if (pcnt<10)
                str+="    ";
            else if (pcnt<100)
                str+="   ";
            else if (pcnt<1000)
                str+="  ";
            else str+=" ";
            //status->append(txtstr);
            //count++;


            if (size_ip < 20) {
                sprintf(txtstr,"   * Invalid IP header length: %u bytes", size_ip);
                str+=txtstr;
                //status->append(txtstr);
                return;
            }
            int i,k;
            sprintf(txtstr,"%s", inet_ntoa(ip->ip_src));
            str+=txtstr;
            k=strlen(inet_ntoa(ip->ip_src));
            if (k<15)
            {
                for (i=0;i<15-k;i++)
                    str+=" ";
            }

            //status->append(txtstr);
            sprintf(txtstr,"%s", inet_ntoa(ip->ip_dst));
            str+=txtstr;
            k=strlen(inet_ntoa(ip->ip_dst));
            if (k<15)
            {
                for (i=0;i<15-k;i++)
                    str+=" ";
            }

            //status->append(txtstr);
            sprintf(txtstr," %d ", header->len);
            str+=txtstr;
            if (header->len<10)
                str+="    ";
            else if (header->len<100)
                str+="   ";
            else if (header->len<1000)
                str+="  ";
            else
                str+=" ";

            ltime=localtime(&header->ts.tv_sec);
            strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
            sprintf(timeS,"  %s.%.6d", timestr, header->ts.tv_usec);
            //sprintf(txtstr,"  time %.6d", header->ts.tv_usec);
            //str+=txtstr;
            //status->append(txtstr);

            //sprintf(txtstr,"       Time: %f", header->ts);
            //status->append(txtstr);

#ifdef WIN32
            country="   (This option is only for Linux)";
#else
            if (scountry=GeoIP_country_code_by_addr(gi,inet_ntoa(ip->ip_src)))
            {
                sprintf(txtstr,"   %s            ",scountry);
                country=txtstr;
            }
            else
                country="   -             ";

            if (dcountry=GeoIP_country_code_by_addr(gi,inet_ntoa(ip->ip_dst)))
            {
                sprintf(txtstr,"%s           ",dcountry);
                country+=txtstr;
            }
            else
                country+="-            ";

#endif

            //if (strlen(txtstr)!=0)
            //str+=txtstr;
            //if (strlen(txtstr)==2)
            //    str+="           ";
            //else
            //    str+="         ";
            //sprintf(txtstr,"%s",GeoIP_country_name_by_addr(gi,inet_ntoa(ip->ip_dst)));
            //str+=txtstr;

            /* determine protocol */

            switch(ip->ip_p) {
            case IPPROTO_TCP:
                sprintf(txtstr,"   TCP      ");
                str+=txtstr;
                str+=timeS;
                str+=country;
                //status->append(str);

                break;
            case IPPROTO_UDP:
                sprintf(txtstr,"   UDP      ");
                str+=txtstr;
                str+=timeS;
                str+=country;
                status->append(str);
                status->append("--------------------------------------------------------------------------------------------------------");
                return;
            case IPPROTO_ICMP:
                sprintf(txtstr,"   ICMP     ");
                str+=txtstr;
                str+=timeS;
                str+=country;
                status->append(str);
                status->append("--------------------------------------------------------------------------------------------------------");
                return;
            case IPPROTO_IP:

                sprintf(txtstr,"   IP       ");
                str+=txtstr;
                str+=timeS;
                str+=country;
                status->append(str);
                status->append("--------------------------------------------------------------------------------------------------------");
                return;
            default:
                sprintf(txtstr,"   unknown   ");
                str+=txtstr;

                str+=timeS;
                str+=country;
                status->append(str);
                status->append("--------------------------------------------------------------------------------------------------------");

                error=true;
                result="Unknown protocol";
                emit onLoad();
                error=false;


                return;
            }

            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                sprintf(txtstr,"   * Invalid TCP header length: %u bytes", size_tcp);
                status->append(txtstr);
                return;
            }

            sprintf(txtstr,"\nSrc. port: %d\n", ntohs(tcp->th_sport));
            str+=txtstr;
            //status->append(txtstr);
            sprintf(txtstr,"Dst. port: %d", ntohs(tcp->th_dport));
            str+=txtstr;
            status->append(str);

            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

            if (size_payload > 0) {
                sprintf(txtstr,"   Payload (%d bytes):", size_payload);
                str+=txtstr;
                status->append(txtstr);

                print_payload(payload, size_payload);
            }
            status->append("--------------------------------------------------------------------------------------------------------");
        }
        else if (wekaview)
        {
            str="";
            bool pr=false;
            int i;
            int lenTemp;
            char *ipTemp;
            char ipTemp_[16];

            ipTemp=inet_ntoa(ip->ip_src);

            i=0;
            while ((ipTemp_[i]=ipTemp[i++])!='\0');
            for (i=0;i<sipC;i++)
                if (strcmp(srcipARR[i],ipTemp)==0)
                {
                    pr=true;
                    break;
                }
            if (!pr)
            {
                i=0;
                while ((srcipARR[sipC][i]=ipTemp_[i++])!='\0');
                sipC++;
            }
            sprintf(txtstr,"%s,",ipTemp);
            str+=txtstr;

            pr=false;
            i=0;
            ipTemp=inet_ntoa(ip->ip_dst);
            while ((ipTemp_[i]=ipTemp[i++])!='\0');
            for (i=0;i<dipC;i++)
                if (strcmp(dstipARR[i],ipTemp)==0)
                {
                    pr=true;
                    break;
                }
            if (!pr)
            {
                i=0;
                while ((dstipARR[dipC][i]=ipTemp_[i++])!='\0');
                dipC++;
            }
            sprintf(txtstr,"%s,",ipTemp);
            str+=txtstr;

            pr=false;
            i=0;
            lenTemp=header->len;
            for (i=0;i<lenC;i++)
                if (lenTemp==lenARR[i])
                {
                pr=true;
                break;
                }
            if (!pr)
            {
                lenARR[lenC]=lenTemp;
                lenC++;
            }
            sprintf(txtstr,"%d,",lenTemp);
            str+=txtstr;

            char *pTemp;
            char pTemp_[8];

            switch(ip->ip_p)
            {
            case IPPROTO_TCP:
                sprintf(txtstr,"TCP,");
                pTemp="TCP";
                break;
            case IPPROTO_UDP:
                sprintf(txtstr,"UDP,");
                pTemp="UDP";
                break;
            case IPPROTO_ICMP:
                sprintf(txtstr,"ICMP,");
                pTemp="ICMP";
                break;
            case IPPROTO_IP:
                sprintf(txtstr,"IP,");
                pTemp="IP";
                break;
            default:
                sprintf(txtstr,"unknown,");
                pTemp="unknown";
                break;
            }
            pr=false;
            i=0;

            while ((pTemp_[i]=pTemp[i++])!='\0');
            for (i=0;i<protC;i++)
                if (strcmp(protARR[i],pTemp)==0)
                {
                    pr=true;
                    break;
                }
            if (!pr)
            {
                i=0;
                while ((protARR[protC][i]=pTemp_[i++])!='\0');
                protC++;
            }
            sprintf(txtstr,"%s,",pTemp);

            str+=txtstr;

            #ifdef WIN32
            country="NO";
#else
            char *cntry;
            char cntry_[3];
            if (scountry=GeoIP_country_code_by_addr(gi,inet_ntoa(ip->ip_src)))
            {
                sprintf(txtstr,"%s,",scountry);
                country=txtstr;
                cntry=(char*)scountry;
            }
            else
            {
                country="@@,";
                cntry="@@";
            }

            pr=false;
            i=0;

            while ((cntry_[i]=cntry[i++])!='\0');
            for (i=0;i<sCC;i++)
                if (strcmp(srcCARR[i],cntry)==0)
                {
                    pr=true;
                    break;
                }
            if (!pr)
            {
                i=0;
                while ((srcCARR[sCC][i]=cntry_[i++])!='\0');
                sCC++;
            }

            pr=false;
            i=0;
            if (dcountry=GeoIP_country_code_by_addr(gi,inet_ntoa(ip->ip_dst)))
            {
                sprintf(txtstr,"%s",dcountry);
                country+=txtstr;
                cntry=(char*)dcountry;
            }
            else
            {
                country+="@@";
                cntry="@@";
            }

            while ((cntry_[i]=cntry[i++])!='\0');
            for (i=0;i<dCC;i++)
                if (strcmp(dstCARR[i],cntry)==0)
                {
                    pr=true;
                    break;
                }
            if (!pr)
            {
                i=0;
                while ((dstCARR[dCC][i]=cntry_[i++])!='\0');
                dCC++;
            }
#endif
        str+=country;

        QDateTime now = QDateTime::currentDateTime();
        str+=',';
        str+=now.toString("M");
        str+=',';
        str+=now.toString("d");

        str+=',';
        str+=now.toString("dddd");
        str+=',';
        str+=now.toString("h");
        str+=',';
        str+=now.toString("m");
        str+=',';
        str+=now.toString("s");
        str+=',';
        str+=now.toString("z");
        str+=',';
        str+=now.toString("ap");
        QString dn=now.toString("h");
        bool ok1;
        int h = dn.toInt(&ok1, 10);
        str+=',';
        if (h>=0&&h<=7)
            str+="night";
        else if (h>=8&&h<=15)
            str+="day";
        else if (h>=16&&h<=23)
            str+="evening";
        //printf("%d %d %d\n",time.hour(),time.minute(),time.second());

        status->append(str);

        }
        return;
}
