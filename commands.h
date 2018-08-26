/* ---------------------------------------------------------------------------------- 
 * Applied Expert Systems, inc.
 * Copyrighted proprietary intellectual property.
 *
 * This header contains interface definitions for real-time comunications between
 * the monitor and the reporting clients.
 * TCP socket connection is via INNA registered port 6687
 * send and recieve buffers are structured as describe below.  Unstructured buffer
 * send from TcpClients are discards.
 *
 * Author: Mark Nguyen
 * Conceptual: 04/10/2009
 * Last update: 11/04/2009
 *
 * ----------------------------------------------------------------------------------
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/wait.h>  /*****  For waitpid.                   *****/
#include <setjmp.h>    /*****  For sigsetjmp and siglongjmp.  *****/
#include <mysql.h>

//#include "/usr/local/mysql/include/mysql/mysql.h" 

/*-- Licensing --*/
#define ESIZE 256
#define BYTE(x) ((x) & 0xFF)
#define NDELAY 6
#define TRUE 1
#define FALSE 0


#define SERVER_NAME "CleverView TCP/IP on Linux - Monitor"
#define SERVER_PORT 6688           /* listening port enables inet socket connection */
#define PRODUCTCODE 0xABBABABE     /* Require setting in the command header send from client */
#define SHELL       "/bin/sh"      /* system shell command */
#define BIG_RPYBUFFLEN    8192     /*  2 kB */
#define SMALL_RPYBUFFLEN  1024
#define CMDBUFFLEN  1024
#define MAXRPYBYTES 12288         /* maximum number of 10k bytes in output buffer */
#define LIC_FILENAME "/usr/share/cv4linux/license.txt"
#define RC_FILENAME "/usr/share/cv4linux/remotectrl.cfg"
#define CNAMESIZE 256

#define LOG_DIR                "/tmp"         /* logging directory */
#define LOG_FILE               "cvtcpipl_node_mon.log"    /* node's mib monitoring log */
#define OLD_LOG_FILE           "cvtcpipl_node_mon.log-old" /* previous mib monitoring log */
#define LOCK_FILE              "cvtcpipl_node_mon.lock"   /* daemon pid lock */
#define MIBMON_SCRIPT_DIR      "/usr/local/aes/scripts"   /* deploy directory for monitoring scripts */
#define RUNNING_DIR            "/usr/local/aes"           /* application root directory */
#define NODE_MON_INTV          300                        /* Default 5 minutes node monitoring interval */
#define PORT_MON_INTV          300                        /* Default 5 minutes port monitoring interval */
#define CRIT_RES_MON_INTV      300                        /* Default 5 minutes critical resource monitoring interval */
#define OSA_MON_INTV           300                        /* Default 5 minutes OSA adapter moitoring interval */
#define KVM_MON_INTV           300                        /* Default 5 minutes KVM adapter moitoring interval */
#define DOCKER_MON_INTV        300                        /* Default 5 minutes docker adapter moitoring interval */
#define TINY_RPYBUFFLEN   512
 
/* enumurated directives used in structures below */
#define CMD_NO_DIRECTIVE              0
#define CMD_START_DIRECTIVE           1
#define CMD_STOP_DIRECTIVE            2
#define CMD_STATUS_DIRECTIVE          3
#define CMD_PING_DIRECTIVE            4
#define CMD_TRACERT_DIRECTIVE         5
#define CMD_NETSTAT_DIRECTIVE         6
#define CMD_NSLOOKUP_DIRECTIVE        7
#define CMD_PORT_STATUS_DIRECTIVE     8
#define CMD_ALL_PORT_STATUS_DIRECTIVE 9
#define CMD_UPLOAD_DIRECTIVE          10
#define CMD_TRACERT6_DIRECTIVE        11
#define CMD_PING6_DIRECTIVE           12
#define CMD_REMOTECTRL_DIRECTIVE      13                /* Interface with PLINK to enable remote script execution */
#define CMD_REMOTECTRL_TEST_DIRECTIVE 14                /* Used for internal testing */

/*-- SysView --*/
#define CMD_SYSVIEW_DIRECTIVE        15
/*-- DockerView --*/
#define CMD_DOCKERVIEW_DIRECTIVE     16

/*-- SysView sub commands --*/
#define CMD_SYSVIEW_CPU_INFO         17
#define CMD_SYSVIEW_DEVICE_DRIVER    18
#define CMD_SYSVIEW_FILE_LOCKS       19
#define CMD_SYSVIEW_FILE_SYSTEM      20
#define CMD_SYSVIEW_IO_PORTS         21
#define CMD_SYSVIEW_IO_STATS         22
#define CMD_SYSVIEW_ARP_TABLE        23
#define CMD_SYSVIEW_MODULES          24
#define CMD_SYSVIEW_MEM_INFO         25

#define CMD_SYSVIEW_NET_CONNECTIONS  26
#define CMD_SYSVIEW_NET_INTERFACES   27
#define CMD_SYSVIEW_NET_TCPIPV4      28
#define CMD_SYSVIEW_NET_TCPIPV6      29
#define CMD_SYSVIEW_NET_SOCKET_IPV4  30
#define CMD_SYSVIEW_NET_SOCKET_IPV6  31
#define CMD_SYSVIEW_NET_SUMMARY      32
#define CMD_SYSVIEW_NET_UDP_IPv4     33 
#define CMD_SYSVIEW_NET_UDP_IPV6     34

#define CMD_SYSVIEW_OPEN_FILES       35
#define CMD_SYSVIEW_PROCESS_STATS    36
#define CMD_SYSVIEW_SYSTEM_STATS     37
#define CMD_SYSVIEW_PARTITIONS       38

/*-- DockerView sub commands --*/
#define CMD_DOCKER_CONTAINER_ACTIVE_STATS       40
#define CMD_DOCKER_CONTAINER_ALL_STATS          41
#define CMD_DOCKER_CONTAINTER_ACTIVE_SUMMARY    42
#define CMD_DOCKER_CONTAINTER_ALL_SUMMARY       43
#define CMD_DOCKER_IMAGE_LIST                   44
#define CMD_DOCKER_HOSTING_INFO                 45

#define CMD_DOCKER_CONTAINER_DIFF               46
#define CMD_DOCKER_CONTAINER_INSPECT            47
#define CMD_DOCKER_CONTAINER_LOGS               48
#define CMD_DOCKER_CONTAINER_TOP                49
#define CMD_DOCKER_IMAGE_HISTORY                50

#define CMD_DOCKER_CONTAINER_CPUUSAGE                51
#define CMD_DOCKER_CONTAINER_MEMUSAGE                52


/* ---------------------------------------------------------------------------------------*/
/* Management command codes used in conjunction with the enumurated directive above       */
/* e.g. CmdCode = CMDCODE_CRITRES_MONITORING, CmdDirective = CMD_START_DIRECTIVE          */
/*      structure contains settings above will start the critical resource monitoring     */ 
/*----------------------------------------------------------------------------------------*/
#define CMDCODE_CRITRES_MONITORING  0x4001  /* Critical resource monitoring               */
#define CMDCODE_PORTMON_MONITORING  0x4002  /* Port monitoring                            */
#define CMDCODE_MIB_MONITORING      0x4003  /* Node monitoring                            */
#define CMDCODE_NOTIFICATION        0x4004  /* Notification via snmptrap, etc.            */
#define CMDCODE_REALTIME_SYSUTIL    0x4005  /* Real-time system commands                  */ 
                                            /* (ping, tracert, netstat,nslookup,...       */
#define CMDCODE_CONNEXP_TCP_LSTRS   0x4006  /* Real-time connect expert - TCP listeners   */
#define CMDCODE_CONNEXP_UDP_LSTRS   0x4007  /* Real-time connect expert - UDP listeners   */
#define CMDCODE_CONNEXP_CONNECTIONS 0x4008  /* Real-time connect expert - TCP connections */
#define CMDCODE_SNMP_STATUS         0x4009  /* SNMP Status of remote node                 */
#define CMDCODE_DEBUG_LOG           0x4010  /* Upload monitor log to designated web site  */

/*------------------------------------------------------------------------------------------*
 * Datatype reference                                                                       *
 *------------------------------------------------------------------------------------------*
 * KEYWORD               TYPE	                    SIZE(Bits)      RANGE                   *
 *------------------------------------------------------------------------------------------*
 * char                  Char or signed char           8          -128 to 127               *
 * unsigned char         Unsigned char                 8          0 to 255                  *
 * signed int or int     Int or signed int             16         -32768 to 32767           *
 * unsigned int          Unsigned int                  16         0 to 32767                *
 * short                 Short int or signed short int 8          0 to 65535                * 
 * unsigned short        Unsigned short int            8          -128 to 127               *
 * long                  Long int or signed long int   32         -2147483648 to 2147483647 *
 * unsigned long         Unsigned long int             32         0 to 4294967295           *
 * float                 Float                         32         3.4e-38 to 3.4e+38        *
 * double                Double                        64         1.7e-308 to 1.7e+308      *
 * long double           Long double                   80         3.4e-4932 to 3.4e+4932    *
 *------------------------------------------------------------------------------------------*/

typedef struct {
    char monitorname[100];
    char monitorip[40];
    char critresip[40];    
    char critresname[100];
    int  packetsize;
    short MonNow;
    int   threshold;
    int   repeat;
    char  condition[2];
    #define GT     1
    #define EQ     2
    #define LT     3
    #define GE     4
    #define LE     5
} critresdef_t;

/*---------------------------------------*/
/* Common control command header         */
/*---------------------------------------*/
typedef struct {
        int                CmdLength;           /* Command buffer length */
        int                ProdCode;            /* Product code defined as PRODUCTCODE */
	int                CmdCode;             /* Command code defined as CMDCODE_.... */
	unsigned short      CmdDirective;        /* Sub-command code defined as CMD_xxx_DIRECTIVE below */
        char    CmdString[CMDBUFFLEN];           /* full command string as if run from a command prompt */
} CtrlCmdHeader_t, *ControlCmdHeaderPTR;


typedef struct {
        int                CmdLength;           /* Command buffer length */
        int                ProdCode;            /* Product code defined as PRODUCTCODE */
	int                CmdCode;             /* Command code defined as CMDCODE_.... */
	unsigned short      CmdDirective;        /* Sub-command code defined as CMD_xxx_DIRECTIVE below */
        char    CmdString[CMDBUFFLEN];           /* full command string as if run from a command prompt */
} ClientCtrlCmdHeader_t, *ClientControlCmdHeaderPTR;


//        #define CMD_START_DIRECTIVE    1         /* Start CritRes/Port/Node monitoring, CmdString is ignored */  
//        #define CMD_STOP_DIRECTIVE     2         /* Stop CritRes/Port/Node monitoring, CmdString is ignored */
//        #define CMD_STATUS_DIRECTIVE   3         /* Request monitoring status, CmdString is ignored */
//        #define CMD_PING_DIRECTIVE     4         /* Real-time ping command, CmdString is required and will be executed */
//        #define CMD_TRACERT_DIRECTIVE  5         /* Traceroute command, CmdString is required and will be executed */
//        #define CMD_NETSTAT_DIRECTIVE  6         /* netstat command, CmdString is required and will be executed */ 
//        #define CMD_NSLOOKUP_DIRECTIVE 7         /* nslookup command, CmdString is required and will be executed */
//        #define CMD_PORT_STATUS_DIRECTIVE     8
//        #define CMD_ALL_PORT_STATUS_DIRECTIVE 9
//        #define CMD_UPLOAD_DIRECTIVE          10


/*---------------------------------*/
/* Common reply header             */
/*---------------------------------*/
typedef struct {
	short	 ReturnCode;
	short	 ReasonCode;
	int	 RpyBufferLength;
	int	 ProdCode;
	int 	 RpyEntries;
        char     Output[BIG_RPYBUFFLEN];
} RpyHeader_t, *ReplyHeaderPTR; 

typedef struct {
        ReplyHeaderPTR rpyhdr;
        char       rpybuf[BIG_RPYBUFFLEN];
} RpyRealtime_t, *ReplyRealtimePTR;


typedef struct {
    char prodDesignation[3];
    char companyname[80];
    char shippingaddress[200];
    char maxnodes[6];
    char maxusers[6];
    char expiration[14];
    char mobile_expiration[14];
    char hostid[16];
    int  isTrial;
    char option[200];
    char unoption[150];
    char opcode[50];
    char mobile[6];
    char sysview[6];
    char blockchainview[6];
} Lic_t, *LicPTR;

typedef struct {
    char monitorip[40];
    char sqlcmdstmt[1024];
} mySqlCmd_t, *mySqlCmdPTR;


typedef struct {
    char actionlabel[100];
    char actiontype[15];
    char targetip[40];
    char targetuserid[40];
    char targetpasswd[50];
    char privatekey[200];
    char actionsource[150];
    char args[100];
    char isSudo[8];
    int  isFound;
} remoteCmd_t, *remoteCmdPTR;


extern void log_message(char *filename, char *message);
extern char *IntToStr( char *str, int num);
extern char *StrConcat( char *str1, char *str2);
extern char *getComunityName(char *SVERIP);
extern int mySQLexec(mySqlCmd_t *MYSQLCMD);
extern char* getIP(const char* interface);
//extern double isExpired(char *dateval);
extern int* dt_parser(char *dt);
extern int isValidChksum(char optionval[], long validVal);
extern int getRandInt();
extern char hexToAscii(char first, char second);
extern int is_numeric(const char *p);
//extern void aescrypt(char ins[], char outs[], int len);
extern void shuffle(int a[], int size, int rstream);
extern int rand8(int i);
extern int validatelicense();
extern int is_valid_ip(const char *ip_str);

/*
extern get_date_interval_value(const char* intvtype);
extern to_epoch(const char* intvtype, double multiple);
extern from_epoch(const char* intvtype, time_t tv);
extern double hms_to_frac(int hour, int min, int sec);
extern void frac_to_hms(double frac, int* hour, int* min, int*sec);
extern struct tm mk_tm(int year, int month, int day, int hour, int minute, int second);
*/


