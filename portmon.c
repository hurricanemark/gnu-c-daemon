#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

#define MAX_TCP_CON      9
#define MAX_PART         20
#define STD_MSN_PORT     1863
#define OUTPUT_LOCALITY  "scanportout.txt"
#define MAXIPLEN 17
#define MAXNAMELEN 128

#undef  atoi             /* redefined atoi with my own function */

char user[10];
char recvbuff[128];
char filebuff[255];
int tmp, port2scan;
int result;
int closed;
int sock_con(char *host, int port, int ttl);


FILE *wfp;
fpos_t file_loc;
char filename[64];
extern char outputfile[64];


struct sockaddr_in sock;        /* Structure for socket address         */
long address;                   /* Remote IP (4 octet) address          */
struct hostent *ph;
int tcp_sock;
int args[2][1];
char print[512];
struct in_addr **pptr;
int bind_sock;
int con_sock;
int irc_sock;


int file_open();
int file_close();
char outputfile[64];
void banner(char *readbuff, int readsize);
struct hostent *hptr;

/*
1       0       1
1       1       1
0       1       1
banner  filter  scan
*/

char optchar;
int options[10];
int ctr;
extern void print_line();
extern int get_host(char *host, char *dest);
extern int get_emails();
extern int file_prep();
extern int file_open();
extern int file_close();
extern int get_iwhois();
extern int get_nwhois();
extern int get_subdomains();
extern int get_netcraft();
extern int portscan(char *entry, int ttl, int options);
extern int singleportscan(char *entry, int portnum, int ttl, int options);
char outputfile[64];

char *message[]={
"  -p\t Perform a TCP port scan on a host\n",
"  -h\t specified host\n",
"* -f\t Perform a TCP port scan on a host showing output reporting filtered ports\n",
"* -b\t Read in the banner received from the scanned port\n",
"* -t 0-9 Set the TTL in seconds when scanning a TCP port ( Default 2 )\n",
"*Requires the -p flagged to be passed\n",
"Example: portscan -pt 7 -h localhost 21\n"
};


static sigjmp_buf jmpbuf;
static void sig_alrm();
int tmp;

/* Convert a string to an int.  */
int atoi (const char *nptr)
{
  return (int) strtol (nptr, (char **) NULL, 10);
}

int sock_con(char *host, int port, int ttl)
{
     signal(SIGALRM, sig_alrm);
     close(tcp_sock);
     tcp_sock = 0;

     address = inet_addr(host);
     sock.sin_addr.s_addr = address;
     sock.sin_family = AF_INET;
     sock.sin_port = htons(port);
     if((tcp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return 3;
     }
     alarm(ttl);
     #ifdef HAVE_SIGSETJMP_F
     if (sigsetjmp(jmpbuf, 1) != 0 ) {
     #else
     if (__sigsetjmp(jmpbuf, 1) != 0 ) {
     #endif
     return 2;
     }

     if(connect(tcp_sock, (struct sockaddr *) &sock, sizeof (sock)) < 0) {
        return 1;
     }

     return 0;
}

void sig_alrm()
{
        siglongjmp(jmpbuf, 1);
        printf("werd\n");
        return;
}

void banner(char *readbuff, int readsize)
{
        memset(readbuff, '\0', readsize);       /* Clear read buffer (null) */
        read((int) tcp_sock, (char *) readbuff, (int) readsize);
        printf(">> %s\n", readbuff);
}

int file_prep()
{
        outputfile[strlen(outputfile)] = '\0';
        if (!(wfp = fopen(outputfile, "w" ) )) {
                printf("Error: Unable to write to %s\n", outputfile);
                return 1;
        }
        printf("Writing output to '%s'\n\n", outputfile);
        fclose(wfp);
        return 0;
}

int file_open()
{
        if (!( wfp = fopen(outputfile, "a+" ) )) {
                printf("Error: Unable to write to %s\n", outputfile);
                return 1; 
        }
        return 0;
}

int file_close()
{
        if (fclose(wfp)) {
                printf("Error: Unable to close file stream writing to %s\n", outputfile);
                return 1; 
        }
        return 0;
}


/*-----------------------------------------------------------------------------------*/
/* print_line()                                                                      */
/*-----------------------------------------------------------------------------------*/
void print_line(char *string, char *string2)
{
        int ctr;
        int ctr2;
        char sendbuff[255];
        char timebuff[5];
        char timebuff2[5];
        struct tm *timenow;
        time_t now;

        if ( strlen(outputfile) ){
                memset(sendbuff, '\0', sizeof(sendbuff));
                ctr = 0;
                ctr2 = 0;
                do {
                        if ( string[ctr] == '%' && string[ctr + 1] == 's' ){
                                strcat(sendbuff, string2);
                                ctr += 2;
                        }
                        sendbuff[strlen(sendbuff)] = string[ctr];
                        ctr ++;
                } while ( string[ctr] != '\0' );

                fputs(sendbuff, wfp);
        }

        printf(string, string2);

        return;
}




/*-----------------------------------------------------------------------------------*/
/* gethost()                                                                         */
/*-----------------------------------------------------------------------------------*/
int get_host(char *host, char *dest)
{
        char www[128];
        char **pptr;
        unsigned long address;

        if (INADDR_NONE == ( address = inet_addr(host) )){
                /* Grab the IP address using the hostname */

                if (!(hptr = gethostbyname(host))){
                        memset(www, '\0', sizeof(www));
                        snprintf(www, sizeof(www), "www.%s", host);
                        if (!(hptr = gethostbyname(www))){
                                return 0;
                        }
                }
                pptr = hptr->h_addr_list;
                inet_ntop(hptr->h_addrtype, *pptr, dest, MAXIPLEN);
                return 1;
        } else {
                /* Grab the hostname using the IP address */
                if (! (hptr = gethostbyaddr((char *) &address, 4, AF_INET) )) return 0;

                snprintf(dest, MAXNAMELEN, "%s", hptr->h_name);
                return 1;
        }
        return 0;
}


/*-----------------------------------------------------------------------------------*/
/* singleportscan() connects to a specific TCP listening port on target host         */
/*-----------------------------------------------------------------------------------*/
int singleportscan(char *entry, int portnum, int ttl, int options)
{
        if ( strlen(outputfile) ) file_open();
        tcp_sock = 0;
        memset(filebuff, '\0', sizeof(filebuff));
        printf("%s\n", filebuff);
        if ( strlen(outputfile) ) fputs(filebuff, wfp);

        result = sock_con(entry, portnum, ttl);
        if ( result == 0 ){
                memset(filebuff, '\0', sizeof(filebuff));
                if ( portnum < 1000 ) snprintf(filebuff, sizeof(filebuff), "Status: open\n");
                if ( portnum > 1000 ) snprintf(filebuff, sizeof(filebuff), "Status: open\n");
                if ( strlen(outputfile) ) fputs(filebuff, wfp);
                printf("%s", filebuff);
                if ( options >= 100 ){
                        banner(recvbuff, sizeof(recvbuff));
                        if ( recvbuff[strlen(recvbuff) - 1] != '\n' ) recvbuff[strlen(recvbuff) - 1] = '\n';
                        if ( strlen(outputfile) ) fputs(recvbuff, wfp);
                }
        }
        if ( result == 1 ){
                memset(filebuff, '\0', sizeof(filebuff));
                if ( portnum < 1000 ) snprintf(filebuff, sizeof(filebuff), "Status: Not found!\n");
                if ( portnum > 1000 ) snprintf(filebuff, sizeof(filebuff), "Status: Not found!\n");
                if ( strlen(outputfile) ) fputs(filebuff, wfp);
                printf("%s", filebuff);
                closed++;
        }
        if ( result == 2 ){
                memset(filebuff, '\0', sizeof(filebuff));
                if (options == 11 || options == 111){
                        if ( portnum < 1000 ) snprintf(filebuff, sizeof(filebuff), "Status: filtered\n");
                        if ( portnum > 1000 ) snprintf(filebuff, sizeof(filebuff), "Status: filtered\n");
                        if ( strlen(outputfile) ) fputs(filebuff, wfp);
                        printf("%s", filebuff);
                }
        }

        memset(filebuff, '\0', sizeof(filebuff));
        printf("%s\n", filebuff);
        if ( strlen(outputfile) ){
                fputs(filebuff, wfp);
                file_close();
        }
        return 0;
}


/*-----------------------------------------------------------------------------------*/
/* portscan() connects to TCP listening ports on target host                         */
/*-----------------------------------------------------------------------------------*/
int portscan(char *entry, int ttl, int options)
{
        if ( strlen(outputfile) ) file_open();
        tcp_sock = 0;
        memset(filebuff, '\0', sizeof(filebuff));

        snprintf(filebuff, sizeof(filebuff), "\nTCP Port information for %s\n---------------------------------------\n\n Port\t\tState\n", entry);
        printf("%s\n", filebuff);
        if ( strlen(outputfile) ) fputs(filebuff, wfp);
        for(tmp=1;tmp < 150;tmp++){
                result = sock_con(entry, tmp, ttl);
                if ( result == 0 ){
                        memset(filebuff, '\0', sizeof(filebuff));
                        if ( tmp < 1000 ) snprintf(filebuff, sizeof(filebuff), "%d/tcp\t\topen\n", tmp);
                        if ( tmp > 1000 ) snprintf(filebuff, sizeof(filebuff), "%d/tcp\topen\n", tmp);
                        if ( strlen(outputfile) ) fputs(filebuff, wfp);
                        printf("%s", filebuff);
                        if ( options >= 100 ){
                                banner(recvbuff, sizeof(recvbuff));
                                if ( recvbuff[strlen(recvbuff) - 1] != '\n' ) recvbuff[strlen(recvbuff) - 1] = '\n';
                                if ( strlen(outputfile) ) fputs(recvbuff, wfp);
                        }
                }
                if ( result == 1 ){
                        closed++;
                }
                if ( result == 2 ){
                        memset(filebuff, '\0', sizeof(filebuff));
                        if (options == 11 || options == 111){
                                if ( tmp < 1000 ) snprintf(filebuff, sizeof(filebuff), "%d/tcp\t\tfiltered\n", tmp);
                                if ( tmp > 1000 ) snprintf(filebuff, sizeof(filebuff), "%d/tcp\tfiltered\n", tmp);
                                if ( strlen(outputfile) ) fputs(filebuff, wfp);
                                printf("%s", filebuff);
                        }
                }
        }
        memset(filebuff, '\0', sizeof(filebuff));
        snprintf(filebuff, sizeof(filebuff), "\nPortMon Finished: Found %d ports were in state closed\n", closed);
        printf("%s\n", filebuff);
        if ( strlen(outputfile) ){
                fputs(filebuff, wfp);
                file_close();
        }
        return 0;
}


/*----------------------------------------------------------------------------------*/
/* main program                                                                     */
/*----------------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
        int ttl = 2;            /*Portscan TimeToLive*/
        int otherops = 0;       /*Are there any other options selected other than fileoutput (-o) */
        char host_ip[MAXIPLEN];
        char host_name[MAXNAMELEN];
        int optchar;
        memset(host_name, '\0', MAXNAMELEN);
        memset(host_ip, '\0', MAXIPLEN);
        port2scan = 0;


        memset(outputfile, '\0', sizeof(outputfile));

        if ( argc == 1 ){
                printf("Usage: %s [-pfb] [-t 0-9] [-o %%host.txt] [-h host] port\n", argv[0]);
                for(ctr=0;ctr < 6;ctr++){
                        printf("%s", message[ctr]);
                }
                return 1; 
        }

        /* The following set is for the command line options used (-pftoh) */
        while ( ( optchar = getopt(argc, argv, "vpbfoh:t:") ) != -1 ){
                switch(optchar){
                        case 'p':
                                options[3] += 1;
                                otherops = 1;
                                break;

                        case 't':
                                if (!isdigit(optarg[0])){
                                        printf("Error: TTL invalid, acceptable range 0-9\n");
                                        printf("Exampe: %s -p -t 9 host\n", argv[0]);
                                        return 0;
                                }
                                else ttl = optarg[0] - 48;
                                otherops = 1;
                                break;

                        case 'f':
                                options[3] += 10;
                                otherops = 1;
                                break;

                        case 'b':
                                options[3] += 100;
                                otherops = 1;
                                break;

                        case 'o':
                                if (! strcmp(optarg, argv[argc-1])){
                                        snprintf(outputfile, sizeof(outputfile), "%s.txt", argv[argc-1]);
                                }
                                else {
                                        strcpy(outputfile, optarg);
                                }
                                break;
                        case 'h':
                                strcpy(host_name, argv[argc - 2]);
                                break;
                        case 'v':
                                printf("Version: cv4tcpipl PortMon/1.0 (Linux)\n");
                                return 1; 
                        default:
                                printf("Usage: %s [-pfb] [-t 0-9] [-o %%host.txt] host\n", argv[0]);
                                for(ctr=0;ctr < 5;ctr++){
                                        printf("%s", message[ctr]);
                                }
                                return 1;
                }
        }

        /* If no options are select then assume
        default that are all to be carried out */
        if (! otherops ){
                options[0] = 1;
                options[1] = 1;
                options[2] = 1;
                options[3] = 1;
                options[4] = 1;
                options[5] = 1;
        }

        /* Potscan options */
        if ( options[3] == 100 || options[3] == 10 || options[3] == 110 ){
                printf("Error: No '-p' flag passed with TTL, assuming -p\n");
                options[3] += 1;
        }

        /* Is the data to be output to a file? */
        if ( strlen(outputfile) ) file_prep();
        if ( strlen(outputfile) ) file_open();

        /* is valid port range? */
        if (strlen(argv[argc - 1]) > 0) {
             port2scan = atoi(argv[argc - 1]);
        }

        /* Check if host exists/is available and resolve */
        switch(inet_addr(argv[argc - 2])){
                case INADDR_NONE:
                        if (! get_host(argv[argc - 2], host_ip) ) {
                                print_line("WARNING: Unable to locate Host IP addr. for %s\t", argv[argc - 2]);
                                print_line("Continue...\n", "");
                        }
                        strcpy(host_name, argv[argc - 2]);
                        break;
                default:
                        if (! get_host(argv[argc - 2], host_name) ) {
                                print_line("WARNING: Unable to locate Host Name for %s\t", argv[argc - 2]);
                                print_line("Continue...\n", "");
                        }
                        strcpy(host_ip, argv[argc - 2]);
                        break;
        }
        print_line("HostIP:\t%s\n", host_ip);
        //print_line("HostName:%s\n", host_name);
        print_line("Port:\t%d\n", port2scan);
        if ( strlen(outputfile) ) file_close();

        /* Scanning Functions */
        if ( options[3] >= 1 && strlen(host_ip) && port2scan == 0) portscan(host_ip, ttl, options[3]);
        if ( options[3] >= 1 && strlen(host_ip) && port2scan > 0) singleportscan(host_ip, port2scan, ttl, options[3]);
        print_line("PortMon completed.\n", "");

        return 0;
}

