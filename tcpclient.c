/************tcpclient.c************************/
/* Header files needed to use the sockets API. */
/* File contains Macro, Data Type and */
/* Structure definitions along with Function */
/* prototypes. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include "commands.h"   /* contains structures and defined definitions for TCP communications in CV4TCP/IP Linux */



/* Default host name of server system. Change it to your default */
/* server hostname or IP.  If the user do not supply the hostname */
/* as an argument, the_server_name_or_IP will be used as default*/


/*--- argv[1] if the server running cv4rtdaemon program
 *--- argv[2] is the node being selected
 *---*/ 

/* Pass in 3 parameter which is either the */
/* address or host name of the server, or */
/* set the server name in the #define SERVER_NAME ... */
int main(int argc, char *argv[])
{
    
     int yachoice = 0;
     time_t mydtime;
        
     /* Variable and structure definitions. */
     int sd, rc, length = sizeof(int);

     struct hostent *hostp;
     struct sockaddr_in serveraddr;
     char buffer[CMDBUFFLEN];
     char server[255];

     ClientCtrlCmdHeader_t *cmdBuffer;
     RpyHeader_t     *rpyBuffer;

     char temp;
     int totalcnt = 0;
     mydtime = time (NULL);
     char *selnode = (char *) malloc (sizeof(char) * 54);
     if (argc >= 2 ) {
         strcpy(selnode, argv[1]);
     } else {
         //strcpy(selnode, "137.72.43.128");
         strcpy(selnode, "i148.100.33.39");
     }
printf("DEBUG: selnoe:%s\n\n", selnode);

     yachoice = (int *) malloc(sizeof(int *));
     while (1) {
	printf ("-----------------------------UNIT_TEST PROGRAM-----------------------------\n");
	printf ("--          Cleverview TCP/IP on LinuxZ (Real-time commands)             --\n");
	printf ("---------------------------------------------------------------------------\n");
/*
	printf ("Real-time CRITICAL RESOURCE tests:\n");
        printf ("\t1. Critical Resource ping:     'ping6 -I eth0 -c3 -s64 -w100 fe80::212:3fff:fef0:ae2e'\n");
        printf ("\t2. Critical Resource traceroute:  'traceroute6 -m15 -i eth0 fe80::212:3fff:fef0:ae2e'\n");
        printf ("\t3. Critical Resource NetStat:  'netstat --tcp -i' -- display interface table.\n");
        printf ("\t4. Critical Resource nslookup: 'nslookup www.aesclever.com'\n");
	printf ("Real-time CONNECT EXPERT tests:\n");
        printf ("\t5. TCP Listeners on %s\n", argv[1]);
        printf ("\t6. UDP Listeners on %s\n", argv[1]);
        printf ("\t7. TCP Connections on %s\n", argv[1]);
	printf ("Real-time PortMon tests:\n");
        printf ("\t8. Status of port 80 on www.aesclever.com\n");
        printf ("\t9. Status of all active listening ports on www.aesclever.com\n");
	printf ("START, STOP, STATUS tests:\n");
        printf ("\t10. Start Node monitoring\n");
        printf ("\t11. Stop Node monitoring\n");
        printf ("\t12. Start Port monitoring\n");
        printf ("\t13. Stop Port monitoring\n");
        printf ("\t14. Start Critical Resources monitoring\n");
        printf ("\t15. Stop Critical Resources monitoring\n");
        printf ("\t16. Upload monitor log\n");
        printf ("\t17. Critical Resource monitoring status\n");
        printf ("\t18. PortMon monitoring status\n");
        printf ("\t19. Node monitoring status\n");
	printf ("PuTTY tests(REMOTE CONTROLS):\n");
        printf ("\t20. (Direct) command: plink -2 -batch -pw markn123 markn@137.72.43.136 -m $(cat /etc/cv4env.conf)/marktestplink.sh\n");
        printf ("\t21. (User-defined script) command: 'Query IPv6 Address' 137.72.43.136 markn markn123\n");
        printf ("\t22. (System default command) command: 'List system log folder' 137.72.43.136 markn markn123\n");
        printf ("\t23. (System default command--require sudo) command: 'Create system file at root' 137.72.43.136 markn markn123\n");

        printf ("\t24. (User-defined script) command: 'Query IPv6 Address' 137.72.43.136 csoftqa aesclever8\n");
        printf ("\t25. (System default command) command: 'List system log folder' 137.72.43.136 csoftqa aesclever8\n");
        printf ("\t26. (System default command--require sudo) command: 'Create system file at root' 137.72.43.136 csoftqa aesclever8\n");

        printf ("\t27. (User-defined script) command: 'Query IPv6 Address' 137.72.43.125 csoftqa aesclever8\n");
        printf ("\t28. (System default command) command: 'List system log folder' 137.72.43.125 csoftqa aesclever8\n");
        printf ("\t29. (System default command--require sudo) command: 'Create system file at root' 137.72.43.125 csoftqa aesclever8\n");
*/
        printf ("\n\nTest v2.7 proc stuffs...on selected remote node %s\n", selnode );

        printf ("\t30. CPU Information on %s\n", selnode);
        printf ("\t31. Device drivers on %s\n", selnode);
	printf ("\t32. File Locks on %s\n", selnode);
	printf ("\t33. File Systems on %s\n", selnode);
	printf ("\t34. I/O Ports on %s\n", selnode);
	printf ("\t35. I/O Stats on %s\n", selnode);
	printf ("\t36. ARP Table on %s\n", selnode);
	printf ("\t37. Kernel Modules on %s\n", selnode);
	printf ("\t38. System Memory on %s\n", selnode);
	printf ("\t39. Network Connections on %s\n", selnode);
	printf ("\t40. Network Interfaecs on %s\n", selnode);
	printf ("\t41. Network TCP IPv4 on %s\n", selnode);
	printf ("\t42. Network TCP IPv6 on %s\n", selnode);
	printf ("\t43. Sockets IPv4 on %s\n", selnode);
	printf ("\t44. Sockets IPv6 on %s\n", selnode);
	printf ("\t45. Network Summary on %s\n", selnode);
	printf ("\t46. Network UDP IPv4 on %s\n", selnode);
	printf ("\t47. Network UDP IPv6 on %s\n", selnode);
	printf ("\t48. Open Files on %s\n", selnode);
	printf ("\t49. Process Stats on %s\n", selnode);
	printf ("\t51. System Stats on %s\n", selnode);
	printf ("\t51. System Partitions on %s\n", selnode);
printf("\n");
        //printf ("\n\nTest v2.7 docker stuffs...on selected remote node %s\n", selnode );
        printf ("\n\nTest v2.7 docker stuffs...on selected remote node 148.100.5.191\n");
	printf ("\t60. DockerView--Container--Stats Active\n");
	printf ("\t61. DockerView--Container--Stats All\n");
	printf ("\t62. DockerView--Container--Summary Active\n");
	printf ("\t63. DockerView--Container--Summary All\n");
	printf ("\t64. DockerView--Images\n");
	printf ("\t65. DockerView--Information\n");
	printf ("\t66. DockerView--Container Diff (containerID=8f94a7797dce)\n");
	printf ("\t67. DockerView--Container Inspect (containerID=8f94a7797dce)\n");
	printf ("\t68. DockerView--Container Logs (containerID=8f94a7797dce)\n");
	printf ("\t69. DockerView--Container Top (containerID=8f94a7797dce)\n");
	printf ("\t70. DockerView--Image History (imageID=b3654d32e4f9)\n");
        printf ("\n\nTest v2.8 docker stuffs...on selected remote node 148.100.33.39\n");
	printf ("\t71. DockerView--Container CPU Usage (ContainerID=0b071db2838c)\n");
	printf ("\t72. DockerView--Container Memory Usage (ContainerID=0b071db2838c)\n");
        printf ("\n\n");
	printf ("Enter a test number or 99 to quit:\n");
        scanf( "%d", &yachoice);

        printf("[Client] - You entered %d\n", yachoice);
        if (yachoice == 99) { exit (0); return 0; }
        
	/* prepare the data buffer */
        cmdBuffer = (ClientCtrlCmdHeader_t *) malloc(BIG_RPYBUFFLEN);
        cmdBuffer->ProdCode = htonl(PRODUCTCODE);
        switch (yachoice) {
            case 0:
            case 1: 
              /* ping nad ping6 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 //cmdBuffer->CmdDirective = htons(CMD_PING_DIRECTIVE);
                 //strcpy(cmdBuffer->CmdString, "ping -c3 -s64 -w100 www.CleverSoft.com");
                 cmdBuffer->CmdDirective = htons(CMD_PING6_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "ping6 -I eth0 -c3 -s64 -w100 fe80::212:3fff:fef0:ae2e");
            break;
            case 2:       
             /* traceroute and traceroute6 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_TRACERT6_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "traceroute6 -m15 -i eth0 fe80::212:3fff:fef0:ae2e");
            break;
            case 3: 
             /* netstat */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_NETSTAT_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "netstat --tcp -i");
            break;
            case 4:
             /* nslookup */
                 cmdBuffer->CmdCode = htonl( CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons( CMD_NSLOOKUP_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "nslookup www.aesclever.com");
            break;
            case 5:
             /* connx-tcp-listeners */
                 cmdBuffer->CmdCode = htonl( CMDCODE_CONNEXP_TCP_LSTRS);
                 cmdBuffer->CmdDirective =  htons(CMD_NO_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, argv[1]);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.216");
                 //strcpy(cmdBuffer->CmdString, "snmpwalk -Osq -v2c -cpublic ");
                 //strcat(cmdBuffer->CmdString, argv[1]);
                 //strcat(cmdBuffer->CmdString, " tcp.tcpListenerTable");
                 //strcat(cmdBuffer->CmdString, " tcp.tcpListenerTable > ./tcplisteners.txt");
            break;
            case 6:
             /* connx-udp-endpoints */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_CONNEXP_UDP_LSTRS);
                 cmdBuffer->CmdDirective =  htons(CMD_NO_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, argv[1]);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.216");
                 //strcpy(cmdBuffer->CmdString, "snmpwalk -Osq -v2c -cpublic ");
                 //strcat(cmdBuffer->CmdString, argv[1]);
                 //strcat(cmdBuffer->CmdString, " udp.udpEndpointTable");
                 //strcat(cmdBuffer->CmdString, " udp.udpEndpointTable > ./udplisteners.txt");
            break;
            case 7:
             /* connx-tcp-connections */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_CONNEXP_CONNECTIONS);
                 cmdBuffer->CmdDirective =  htons(CMD_NO_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, argv[1]);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.216");
                 //strcpy(cmdBuffer->CmdString, "snmpwalk -Osq -v2c -cpublic ");
                 //strcat(cmdBuffer->CmdString, argv[1]);
                 //strcat(cmdBuffer->CmdString, " tcp.tcpConnectionTable");
                 //strcat(cmdBuffer->CmdString, " tcp.tcpConnectionTable > ./tcpconnections.txt");
            break;
            case 8:
             /* Port 80 on www.aesclever.com */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective =  htons(CMD_PORT_STATUS_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "cv4portmon -pfb -t7 www.aesclever.com 80");
                 //strcpy(cmdBuffer->CmdString, "/opt/aes/cv4linux/cv4portmon -pfb -t7 www.aesclever.com 80 > ./portmonout.txt");
            break;
            case 9:
             /* Ports on www.aesclever.com */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective =  htons(CMD_ALL_PORT_STATUS_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "/opt/aes/cv4linux/portscan -pfb -t7 www.aesclever.com");
                 //strcpy(cmdBuffer->CmdString, "/usr/bin/portscan -pfb -t7 www.aesclever.com > ./portscanout.txt");
            break;
            case 10:
             /* Start Local Node Monitoring */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_MIB_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_START_DIRECTIVE);
            break;
            case 11:
             /* Stop Local Node Monitoring */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_MIB_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_STOP_DIRECTIVE);
            break;
            case 12:
             /* Start Port Monitoring */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_PORTMON_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_START_DIRECTIVE);
            break;
            case 13:
             /* Stop Port Monitoring */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_PORTMON_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_STOP_DIRECTIVE);
            break;
            case 14:
             /* Start Critical Resources Monitoring */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_CRITRES_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_START_DIRECTIVE);
            break;
            case 15:
             /* Stop Critical Resources Monitoring */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_CRITRES_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_STOP_DIRECTIVE);
            break;
            case 16:
             /* upload monitor log */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_DEBUG_LOG);
                 cmdBuffer->CmdDirective =  htons(CMD_UPLOAD_DIRECTIVE);
            break;
            case 17:
             /* critical resource monitoring status */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_CRITRES_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_STATUS_DIRECTIVE);
            break;
            case 18:
             /* portmon monitoring status */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_PORTMON_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_STATUS_DIRECTIVE);
            break;
            case 19:
             /* node monitoring status */
                 cmdBuffer->CmdCode =  htonl(CMDCODE_MIB_MONITORING);
                 cmdBuffer->CmdDirective =  htons(CMD_STATUS_DIRECTIVE);
            break;
            case 20:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 //cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_TEST_DIRECTIVE);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_TEST_DIRECTIVE);
                 //strcpy(cmdBuffer->CmdString, "plink -2 -pw markn123 markn@137.72.43.136 -m $(cat /etc/cv4env.conf)/marktestplink.sh");
                 //strcpy(cmdBuffer->CmdString, "pscp -2 -pw markn123 $(cat /etc/cv4env.conf)/marktestplink.sh markn@137.72.43.136:marktestplink.sh; plink -2 -pw markn123 markn@137.72.43.136 -m marktestplink.sh");
                 //strcpy(cmdBuffer->CmdString, "pscp -2 -pw markn123 $(cat /etc/cv4env.conf)/marktestplink.sh markn@137.72.43.136:marktestplink.sh");
                 strcpy(cmdBuffer->CmdString, "plink -2 -batch -pw markn123 markn@137.72.43.136 -m marktestplink.sh");
            break;
            case 21:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'Query IPv6 Address' 137.72.43.136 markn markn123");
            break;
            case 22:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'List system log folder' 137.72.43.136 markn markn123");
            break;
            case 23:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'Create system file at root' 137.72.43.136 markn markn123");
            break;
            case 24:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'Query IPv6 Address' 137.72.43.136 csoftqa aesclever8");
            break;
            case 25:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'List system log folder' 137.72.43.136 csoftqa aesclever8");
            break;
            case 26:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'Create system file at root' 137.72.43.136 csoftqa aesclever8");
            break;
            case 27:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'Query IPv6 Address' 137.72.43.125 csoftqa aesclever8");
            break;
            case 28:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'List system log folder' 137.72.43.125 csoftqa aesclever8");
            break;
            case 29:
             /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_REMOTECTRL_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, "'Create system file at root' 137.72.43.125 csoftqa aesclever8");
            break;  




             /*---STARTING TESTS ON V2.7**/
            case 30: /* CPU information on selNode */
                 /* remote control command via plink */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 top -b -n1 -i | head -n5 | grep 'Cpu'");
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/cpuinfo");
            break;
            case 31: /* Device drivers */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/devices");
            break;
            case 32: /* File locks */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " lslocks");
            break;
            case 33: /* File systems */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " mount");
            break;
            case 34: /* io ports on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/ioports");
            break;
            case 35: /* I/O stats on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " iostat");
            break;
            case 36: /* ARP Table on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " arp -n");
            break;
            case 37: /* Kernel modules on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " lsmod");
            break;
            case 38: /* Memory on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/meminfo");
            break;
            case 39: /* Network connections on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " lsof -i -u aes");
            break;
            case 40: /* Interfaces on 147 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " netstat -i | sed 1d");
            break;
            case 41: /* TCP IPv4 on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/net/tcp");
            break;
            case 42: /* Network TCP IPv6 on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/net/tcp6");
            break;
            case 43: /* Socker IPv4 on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/net/sockstat");
            break;
            case 44: /* Socket IPv6 on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/net/sockstat6");
            break;
            case 45: /* Network Summary on 147 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " netstat -s");
            break;
            case 46: /* Network UDP IPv6 on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/net/udp");
            break;
            case 47: /* Socker UDP IPv4 on selnode */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/net/udp6");
            break;
            case 48: /* System open files on 147 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " lsof -i -u aes");
            break;
            case 49: /* Process Stats on 147 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " top -b -n1 | sed 1,6d");
            break;
            case 50: /* System stats on 147 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " top -b -n1 | head -n5");
            break;
            case 51: /* partitions on 147 */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_SYSVIEW_DIRECTIVE);
                 strcpy(cmdBuffer->CmdString, selnode);
                 strcat(cmdBuffer->CmdString, " cat /proc/partitions");
            break;






            case 60: /* CMD_DOCKER_CONTAINER_ACTIVE_STATS */
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_ACTIVE_STATS);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191");
            break;               
            case 61: /*CMD_DOCKER_CONTAINER_ALL_STATS*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_ALL_STATS);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191");

            break;
            case 62: /*CMD_DOCKER_CONTAINTER_ACTIVE_SUMMARY*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINTER_ACTIVE_SUMMARY);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191");

            break;
            case 63: /*CMD_DOCKER_CONTAINTER_ALL_SUMMARY*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINTER_ALL_SUMMARY);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191");

            break;
            case 64: /*CMD_DOCKER_IMAGE_LIST*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_ACTIVE_STATS);
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191");

            break;
            case 65: /*CMD_DOCKER_HOSTING_INFO*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_HOSTING_INFO);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191");

            break;
            case 66: /*CMD_DOCKER_CONTAINER_DIFF*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_DIFF);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191 8f94a7797dce");

            break;
            case 67: /*CMD_DOCKER_CONTAINER_INSPECT*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_INSPECT);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191 8f94a7797dce");

            break;
            case 68: /*CMD_DOCKER_CONTAINER_LOGS*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_LOGS);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191 8f94a7797dce");
            break;

            case 69: /*CMD_DOCKER_CONTAINER_TOP*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_TOP);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 strcpy(cmdBuffer->CmdString, "148.100.5.191 8f94a7797dce");

            break;
            case 70: /*CMD_DOCKER_IMAGE_HISTORY*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_IMAGE_HISTORY);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 //strcpy(cmdBuffer->CmdString, "148.100.5.191 dev-vp2-f2f01b5b62e8587317bcac94f0fb88bdae8956ca11cff2e1a7df32f4b13c505c1098a33cdfed3f5953b8835fd4ea6fca71caba201fe04c19424f7e5ab3d7b6a7");
                 //strcpy(cmdBuffer->CmdString, "148.100.5.191 hyperledger/fabric-baseimage");
                 strcpy(cmdBuffer->CmdString, "148.100.33.39 0b071db2838c");

            break;

            case 71: /*CMD_DOCKER_CONTAINER_CPUUSAGE*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_CPUUSAGE);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 //strcpy(cmdBuffer->CmdString, "148.100.5.191 dev-vp2-f2f01b5b62e8587317bcac94f0fb88bdae8956ca11cff2e1a7df32f4b13c505c1098a33cdfed3f5953b8835fd4ea6fca71caba201fe04c19424f7e5ab3d7b6a7");
                 //strcpy(cmdBuffer->CmdString, "148.100.5.191 hyperledger/fabric-baseimage");
                 strcpy(cmdBuffer->CmdString, "148.100.33.39 0b071db2838c");
            break;

            case 72: /*CMD_DOCKER_IMAGE_HISTORY*/
                 cmdBuffer->CmdCode = htonl(CMDCODE_REALTIME_SYSUTIL);
                 cmdBuffer->CmdDirective = htons(CMD_DOCKER_CONTAINER_MEMUSAGE);
                 //strcpy(cmdBuffer->CmdString, "plink aes@137.72.43.128 -pw aesclever2 docker info");
                 //strcpy(cmdBuffer->CmdString, "137.72.43.128");
                 //strcpy(cmdBuffer->CmdString, "148.100.5.191 dev-vp2-f2f01b5b62e8587317bcac94f0fb88bdae8956ca11cff2e1a7df32f4b13c505c1098a33cdfed3f5953b8835fd4ea6fca71caba201fe04c19424f7e5ab3d7b6a7");
                 //strcpy(cmdBuffer->CmdString, "148.100.5.191 hyperledger/fabric-baseimage");
                 strcpy(cmdBuffer->CmdString, "148.100.33.39 0b071db2838c");
            break;

            case 99:
            default:
             /* exit */
                  printf("[Client] - Bye!\n");
	          exit(0);
                  return 0;
            break;
        }
        cmdBuffer->CmdLength = htonl(strlen(cmdBuffer->CmdString) + sizeof(long *) + sizeof(long *) + sizeof(short *) + sizeof(long *));
        //cmdBuffer->CmdLength = htonl(strlen(cmdBuffer->CmdString) + 14); 


	/*******************************************/
	/* The socket() function returns a socket  */
	/* descriptor representing an endpoint.    */
	/* The statement also identifies that the  */
	/* INET (Internet Protocol) address family */
	/* with the TCP transport (SOCK_STREAM)    */
	/* will be used for this socket.           */
	/*******************************************/

	/* get a socket descriptor */
	if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Client-socket() error");
		exit(-1);
	}
	else
		printf("[Client] - Client-socket() OK\n");

	/*If the server hostname is supplied*/
	if(argc > 1)
	{
		/*Use the supplied argument*/
		strcpy(server, argv[1]);
		printf("[Client] - Connecting to the %s, port %d ...\n", server, SERVER_PORT);
	}
	else
		/*Use the default server name or IP*/
		strcpy(server, SERVER_NAME);

 
	memset(&serveraddr, 0x00, sizeof(struct sockaddr_in));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(SERVER_PORT);


	if((serveraddr.sin_addr.s_addr = inet_addr(server)) == (unsigned long)INADDR_NONE)
	{
		/* When passing the host name of the server as a        */
		/* parameter to this program, use the gethostbyname()   */
		/* function to retrieve the address of the host server. */
		/********************************************************/

		/* get host address */
		hostp = gethostbyname(server);

		if(hostp == (struct hostent *)NULL)
		{
			printf("HOST NOT FOUND --> ");
			/* h_errno is usually defined */
			/* in netdb.h */
			printf("h_errno = %d\n",h_errno);
			printf("---This is a client program---\n");
			printf("Command usage: %s <server name or IP>\n", argv[0]);
			close(sd);
			exit(-1);
		}
		memcpy(&serveraddr.sin_addr, hostp->h_addr, sizeof(serveraddr.sin_addr));
	}

	/* After the socket descriptor is received, the */
	/* connect() function is used to establish a */
	/* connection to the server. */
	/*****************************/
	/* connect() to server. */
	if((rc = connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0)
	{
		perror("Client-connect() error");
		close(sd);
		exit(-1);
	}
	else
		printf("[Client] - Connection established...\n");

 

	/* Send string to the server using write() */
	/*******************************************/
	printf("[Client] - Sending the following command string to the  %s...\n", server);
	printf("\tCommandLength: %d\n", ntohl(cmdBuffer->CmdLength));
	printf("\tProductCode: %X\n", ntohl(cmdBuffer->ProdCode));
	printf("\tCommandCode: %X\n", ntohl(cmdBuffer->CmdCode));
	printf("\tCmdDirective: %d\n", ntohs(cmdBuffer->CmdDirective));
	printf("\tCommandString: %s\n\n", cmdBuffer->CmdString);

	/* Use write() to send the cmdBuffer to the server. */
	rc = write(sd, cmdBuffer, cmdBuffer->CmdLength);

	if(rc < 0)
	{
		perror("[Client] - Client-write() error");
		rc = getsockopt(sd, SOL_SOCKET, SO_ERROR, &temp, &length);
		if(rc == 0)
		{
			/* Print out the asynchronously received error. */
			errno = temp;
			perror("SO_ERROR was");
		}

		close(sd);
		exit(-1);
	}
	else
	{
		printf("[Client] - Client-write() is OK\n");
		printf("[Client] - String successfully sent!\n");
		printf("[Client] - Waiting the %s to echo back...\n", server);
	}


        /* Allocate reply buffer, ready to recieve */
        rpyBuffer = (RpyHeader_t *) malloc(MAXRPYBYTES + 12);
	totalcnt = 0;

	//while(totalcnt < CMDBUFFLEN)
	//{
            if ((totalcnt = recv(sd, rpyBuffer, MAXRPYBYTES + 12, 0)) <= 0) {
                if (totalcnt > 0) {

                } else if (totalcnt < 0) {
		    perror("[Client] - Client-read() error");
		    close(sd);
                } else if (totalcnt == 0) { /* close it */
		    printf("[Client] - Server program has issued a close()\n");
		    close(sd);
                }
            } 
        //}

	printf("[Client] - Client-read() is OK\n\n");
        printf("%sOUTPUT from monitor:\n", ctime(&mydtime));
	printf("\n\tReturnCode: %d\n", ntohs(rpyBuffer->ReturnCode));
	printf("\tReasonCode: %d\n", ntohs(rpyBuffer->ReasonCode));
	printf("\tOutputBufferLength: %d\n", ntohl(rpyBuffer->RpyBufferLength));
	printf("\tNumber of entries: %d\n", ntohs(rpyBuffer->RpyEntries));
	printf("\tCommand output: \n%s\n\n\n", rpyBuffer->Output);

	/* Close socket descriptor from client side. */
	close(sd);
    }

    /* normal exit */
    exit(0);
    return 0;
}
