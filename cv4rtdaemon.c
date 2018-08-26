/*--------------------------------------------------------------------------------------------------*/
/* Applied Expert Systems, inc.                                                                     */
/*                                                                                                  */
/*--------------------------------------------------------------------------------------------------*/
/*******Using select() for I/O multiplexing */
#include "commands.h"

#define READ 0
#define WRITE 1
#define LOG
//#define M_DEBUG 1

double get_date_interval_value(const char* intvltype);
time_t to_epoch(const char* intvltype, double multiple);
double from_epoch(const char* intvltype, time_t tv);
double hms_to_frac(int hour, int min, int sec);
void frac_to_hms(double frac, int* hour, int* min, int* sec);
struct tm mk_tm(int year, int month, int day, int hour, int minute, int second);
int is_valid_ip(const char *ip_str);
char *itoa (int value, char *result, int base);
char *replace_str(char *str, char *orig, char *rep);
char *getDataField(char *SVERIP, char *NODEIP, int field);
int run_dockerstat(const int cmd_verbish, int listenchannel, char *userSelStr, char *serverIP, char *basedir);
//int run_sysstat(const int cmd_verbish, int listenchannel, char *nodeIP, char *serverIP, char *basedir);
int run_sysview(int listenchannel, char *userSelStr, char *serverIP, char *basedir);
int run_dockerview(int listenchannel, char *userSelStr, char *serverIP, char *basedir);
void trimse(char * const str);
char *appendAChar2Str(char *cArr, const char c);
char *removeLastCharFromStr(char *cStr);

char * getIPfromCnf();

char * getIPfromCnf()
{
 FILE *fp;
 char *tok=NULL;
 char *strarray[200];
 int i, lineidx;
 tok = (char *) malloc(sizeof(char) * 200);
 fp = fopen("/usr/share/cv4linux/.mysql.cnf","r"); // Open file in Read mode
 lineidx=1;
 while (fscanf(fp, "%s", tok) != EOF)
 {
    strarray[lineidx] = (char *) malloc(sizeof(char) * 256);
    strcpy(strarray[lineidx], tok);
    lineidx++;
    if (lineidx == 14) {
      //printf("%s\n", tok);
      break;
    }
  }
  fclose(fp);
  return tok;
}


char *appendAChar2Str(char *cStr, const char c)
{
    int len = strlen(cStr);
    cStr[len + 1] = cStr[len];
    cStr[len] = c;
    return cStr;
}

char *removeLastCharFromStr(char *cStr)
{
    int len = strlen(cStr);
    cStr[len - 1] = '\0';
    return cStr;
}

char *replace_str(char *str, char *orig, char *rep)
{
  static char buffer[4096];
  char *p;

  if(!(p = strstr(str, orig)))  // Is 'orig' even in 'str'?
    return str;

  strncpy(buffer, str, p-str); // Copy characters from 'str' start to 'orig' st$
  buffer[p-str] = '\0';

  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));

  return buffer;
}




char *itoa (int value, char *result, int base)
{
    if (base < 2 || base > 36) { *result = '\0'; return result; }

    char* ptr = result, *ptr1 = result, tmp_char;
    int tmp_value;

    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
    } while ( value );

    if (tmp_value < 0) *ptr++ = '-';
    *ptr-- = '\0';
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr--= *ptr1;
        *ptr1++ = tmp_char;
    }
    return result;
}



int run_dockerstat(const int cmd_verbish, int listenchannel, char *userSelStr, char *serverIP, char *basedir)
{
   RpyHeader_t  *rpyBuffer;
   pid_t child_dig_pid;
   char *filename = (char *) malloc (sizeof(char) * 350);
   char *CmdSTRING = (char *) malloc (sizeof(char) * 1024);
   char *SockDiffOutFName = (char *) malloc (sizeof(char) * 150);
   char tmpBuffer[1024];
   FILE *fp;
   int byte_count, line_count, word_count;
   size_t RPYHEADERLEN;

   char *token = (char *) malloc (sizeof(char) * 1024);
   const char delim[2] = " ";
   const char *nodeip = (char *) malloc (sizeof(char) * 42);
   const char *cmdtoken = (char *) malloc (sizeof(char) * 400);
   const char *actualCMD = (char *) malloc (sizeof(char) * 650);

   RPYHEADERLEN=14;
   /* expect two or more tokens from userSelStr
    * nodeip = token[0]
    * containerID = token[1]
    */
   word_count=0;
#ifdef M_DEBUG
       printf("userSelStr:%s\n", userSelStr);
#endif

   token = strtok(userSelStr, delim);
   strcpy(nodeip, token);
   strcpy(actualCMD, "");

   /* the following loop gets the rest of the tokens until the
    * end of the string */
   while ((token = strtok(NULL, " ")) != NULL) {
       if (word_count >= 0) {
          strcat(actualCMD, token);
          strcat(actualCMD, " ");
       }
       word_count = word_count + 1;
   }

#ifdef M_DEBUG
       printf("userSelStr:%s wordcnt:%d nodeip:%s actualCMD:%s\n", userSelStr, word_count, nodeip, actualCMD);
#endif

   if (strlen(nodeip) > 0)
   {
       child_dig_pid = fork();
       if (child_dig_pid > 0) {
       /* parent process */
       /* output filename to be used in child_dig_pid */
          strcpy(SockDiffOutFName, basedir);
          strcat(SockDiffOutFName, "/tmp/_dockerout_");
          itoa(child_dig_pid, filename, 10);
          strcat(SockDiffOutFName, filename);
          strcpy(filename, SockDiffOutFName);
          waitpid(child_dig_pid, 0, 0); /* wait until child process finished */
          byte_count=1;
          line_count=0;
          rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
          memset(rpyBuffer->Output, '\0', SMALL_RPYBUFFLEN);
          if((fp = fopen(SockDiffOutFName, "r")) != NULL){
              fflush(fp);
              tmpBuffer[1024] = '\0';
              while(fgets(tmpBuffer, sizeof(tmpBuffer), fp)!=NULL){
                  strcat(rpyBuffer->Output, tmpBuffer);
                  line_count++;
                  byte_count=byte_count+ strlen(tmpBuffer);
                  tmpBuffer[1024] = '\0';
              }
              fclose(fp);
          }
          remove(filename);
          replace_str(rpyBuffer->Output, " encoA", "");
          rpyBuffer->RpyEntries = line_count;
          rpyBuffer->RpyBufferLength = byte_count + RPYHEADERLEN + 1;
          rpyBuffer->ReturnCode = 0;
          rpyBuffer->ReasonCode = 0;
          rpyBuffer->ProdCode = PRODUCTCODE;

          rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
          rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
          rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
          rpyBuffer->ProdCode = htonl(PRODUCTCODE);
          rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
          /* debug check on output contents */
          printf("Replied with %d bytes\nNumber of entries:%d\nHeaderLEN=%d\n", ntohl(rpyBuffer->RpyBufferLength), ntohs(rpyBuffer->RpyEntries), RPYHEADERLEN);
#ifdef M_DEBUG
          printf("Contents:\n%s\n", rpyBuffer->Output);
#endif
          /* send output back to sender */
          if(send(listenchannel, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
              perror("send() error!");

          free(rpyBuffer);  /* deallocate memory (this causes the next query to hang...weird! */
      } else if (child_dig_pid == 0) {
          /* construct the command string */
          remoteCmd_t *REMCtrl;
          REMCtrl = (remoteCmd_t *) malloc(sizeof(RpyHeader_t) * 564 );
          /*****
           *-- 1. retrieve mysql table for action_label
           *****/
          /* get authentication info base on NodeIP */
          strcpy(REMCtrl->targetuserid, getDataField(serverIP, nodeip, 2));
          strcpy(REMCtrl->targetpasswd, getDataField(serverIP, nodeip, 3));
          strcpy(REMCtrl->privatekey, getDataField(serverIP, nodeip, 4));
          strcpy(REMCtrl->targetip, nodeip);   /* remote ip address */

#ifdef M_DEBUG
   printf("DEBUG: Starting run_dockerstat\n");
   printf("listenchannel:%d actualCMD:%s serverIP:%s basedir:%s\n", listenchannel, actualCMD, serverIP, basedir);
   printf("targetuserid:%s targetpasswd:%s privatekey:%s targetip:%s\n", REMCtrl->targetuserid, REMCtrl->targetpasswd, REMCtrl->privatekey, REMCtrl->targetip);
#endif

          /* stuff the commandline */
          /* deal with various putty optional command formats */
          if ( strlen(REMCtrl->privatekey) > 1 && strlen(REMCtrl->targetuserid) > 0 ) {
              strcpy(CmdSTRING, "plink ");
              strcat(CmdSTRING, REMCtrl->targetuserid);
              strcat(CmdSTRING, "@");
              strcat(CmdSTRING, REMCtrl->targetip);
              strcat(CmdSTRING, " -i ");  /* option for private key */
              strcat(CmdSTRING, REMCtrl->privatekey);
              strcat(CmdSTRING, " sudo ");
          } else if (strlen(REMCtrl->targetuserid) > 0 && strlen(REMCtrl->targetpasswd) > 0) {
              //strcpy(CmdSTRING, "echo '");
              //strcat(CmdSTRING, REMCtrl->targetpasswd); 
              //strcat(CmdSTRING, "' | plink ");
              strcpy(CmdSTRING, "plink ");
              strcat(CmdSTRING, REMCtrl->targetuserid);
              strcat(CmdSTRING, "@");
              strcat(CmdSTRING, REMCtrl->targetip);
              strcat(CmdSTRING, " -pw ");
              strcat(CmdSTRING, REMCtrl->targetpasswd);
              strcat(CmdSTRING, " sudo ");
          } else {
              /* configured authentication is not found */
          }


          switch (cmd_verbish) {
              case CMD_DOCKER_CONTAINER_ACTIVE_STATS:
                  strcat(CmdSTRING, " /usr/bin/docker stats --no-stream 2>&1 > ");
              break;
              case CMD_DOCKER_CONTAINER_ALL_STATS:
                  strcat(CmdSTRING, " /usr/bin/docker stats -a --no-stream 2>&1 >  ");
              break;
              case CMD_DOCKER_CONTAINTER_ACTIVE_SUMMARY:
                  strcat(CmdSTRING, " /usr/bin/docker ps -s 2>&1 > ");
              break;
              case CMD_DOCKER_CONTAINTER_ALL_SUMMARY:
printf("DEBUG:run_dockerstat(CMD_DOCKER_CONTAINTER_ALL_SUMMARY)-- userSelStr:%s\n", userSelStr);
                  strcat(CmdSTRING, " /usr/bin/docker ps -a -s > ");
              break;
              case CMD_DOCKER_IMAGE_LIST:
printf("DEBUG:run_dockerstat(CMD_DOCKER_IMAGE_LIST)-- userSelStr:%s\n", userSelStr);
                  strcat(CmdSTRING, " /usr/bin/docker images > ");
              break;
              case CMD_DOCKER_HOSTING_INFO:
printf("DEBUG:run_dockerstat(CMD_DOCKER_HOSTING_INFO)-- userSelStr:%s\n", userSelStr);
                  strcat(CmdSTRING, " /usr/bin/docker info > ");
              break;
              case CMD_DOCKER_CONTAINER_DIFF:
printf("DEBUG:run_dockerstat(CMD_DOCKER_CONTAINER_DIFF)-- userSelStr:%s\n", userSelStr);
                  /* dockersubID contains containerID */
                  strcat(CmdSTRING, " /usr/bin/docker diff ");
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, " > ");
              break;
              case CMD_DOCKER_CONTAINER_INSPECT:
printf("DEBUG:run_dockerstat(CMD_DOCKER_CONTAINER_INSPECT)-- userSelStr:%s\n", userSelStr);
                  /* dockersubID contains containerID */
                  strcat(CmdSTRING, " /usr/bin/docker inspect ");
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, " > ");
              break;
              case CMD_DOCKER_CONTAINER_LOGS:
printf("DEBUG:run_dockerstat(CMD_DOCKER_CONTAINER_LOGS)-- userSelStr:%s\n", userSelStr);
                  /* dockersubID contains containerID */
                  strcat(CmdSTRING, " /usr/bin/docker logs ");
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, " &> ");
              case CMD_DOCKER_CONTAINER_TOP:
printf("DEBUG:run_dockerstat(CMD_DOCKER_CONTAINER_TOP)-- userSelStr:%s\n", userSelStr);
                  /* dockersubID contains containerID */
                  strcat(CmdSTRING, " /usr/bin/docker top ");
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, " > ");
              break;
              case CMD_DOCKER_IMAGE_HISTORY:
printf("DEBUG:run_dockerstat(CMD_DOCKER_IMAGE_HISTORY)-- userSelStr:%s\n", userSelStr);
                  /* dockersubID contains imageID */
                  strcat(CmdSTRING, " /usr/bin/docker history ");
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, " > ");
              break;
              case CMD_DOCKER_CONTAINER_CPUUSAGE:    /*51*/
                  removeLastCharFromStr(actualCMD);
/*TODO: v2.8*/
/* (cat /sys/fs/cgroup/cpuacct/docker/0b071db2838c/cpuacct.stat; cat /sys/fs/cgroup/cpuacct/docker/0b071db2838c/cpuacct.usage_percpu; cat /sys/fs/cgroup/cpu/docker/0b071db2838c/cpu.stat) | cat
*/
printf("DEBUG:run_dockerstat(CMD_DOCKER_CONTAINER_CPUUSAGE: userSelStr:%s\n", userSelStr);
                  strcat(CmdSTRING, " (cat /sys/fs/cgroup/cpuacct/docker/");
                  /* actualCMD contains imageID */
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, "*/cpuacct.stat; cat /sys/fs/cgroup/cpuacct/docker/");
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, "*/cpuacct.usage_percpu; cat /sys/fs/cgroup/cpu/docker/");
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, "*/cpu.stat) | cat > ");
              break;

              case CMD_DOCKER_CONTAINER_MEMUSAGE:    /*52*/
                  removeLastCharFromStr(actualCMD);
/*TODO: for v2.8 */ 
/* cat /sys/fs/cgroup/memory/<CONTAINER ID>/memory.stat */
/* cat /sys/fs/cgroup/memory/docker/memory.stat */
                  strcat(CmdSTRING, " cat /sys/fs/cgroup/memory/docker/");
                  /* actualCMD contains imageID */
                  strcat(CmdSTRING, actualCMD);
                  strcat(CmdSTRING, "*/memory.stat > ");
              break;
          }

          printf("actualCMD=%s\n", actualCMD);

          /* output filename to be used in child_pid */
          strcpy(SockDiffOutFName, basedir);
          strcat(SockDiffOutFName, "/tmp/_dockerout_");
          itoa(getpid(), filename, 10);
          strcat(SockDiffOutFName, filename);
          strcat(CmdSTRING, SockDiffOutFName);
#ifdef M_DEBUG
          printf("clientCmdString=%s\n", CmdSTRING);
#endif

          execl(SHELL, SHELL, "-c", CmdSTRING, NULL);
          _exit(EXIT_FAILURE);
      }
   }
   return 0;
}



int run_sysview(int listenchannel, char *userSelStr, char *serverIP, char *basedir)
{
   RpyHeader_t  *rpyBuffer;
   pid_t child_dig_pid;
   const int CMDIDX = 9;
   char *filename = (char *) malloc (sizeof(char) * 350);
   char *CmdSTRING = (char *) malloc (sizeof(char) * 1024);
   char *SockDiffOutFName = (char *) malloc (sizeof(char) * 150);
   char tmpBuffer[1024];
   FILE *fp;
   int byte_count, line_count, word_count, idx;
   size_t RPYHEADERLEN;
   char const *VALIDSYSVIEWCMDS[9] = {"cat", "top", "lsof", "lsmod", "iostat", "mount", "lslocks", "netstat", "arp"};
   char const *VALIDSYSVIEWCMDSPATH[9] = {"cat", "top", "lsof", "lsmod", "iostat", "mount", "lslocks", "netstat", "arp"};
   int bVALIDCMD = 0;
   char *token = (char *) malloc (sizeof(char) * 1024);
   const char delim[2] = " ";
   const char *nodeip = (char *) malloc (sizeof(char) * 42);
   const char *cmdtoken = (char *) malloc (sizeof(char) * 400);
   const char *actualCMD = (char *) malloc (sizeof(char) * 650);
   RPYHEADERLEN=14;
#ifdef M_DEBUG
   printf("DEBUG: Starting run_sysview\n");
   printf("listenchannel:%d userSelStr:%s serverIP:%s basedir:%s\n", listenchannel, userSelStr, serverIP, basedir);
#endif

   /* expect two or more tokens from userSelStr
    * nodeip = token[0]
    * containerID = token[1]
    */
   token = strtok(userSelStr, delim);
   strcpy(nodeip, token);
   /* the following loop gets the rest of the tokens until the
    * end of the string */
   word_count=0;
   while ((token = strtok(NULL, " ")) != NULL) {
       if (word_count == 0) {
           strcpy(cmdtoken, token);
           /*-- posible commands: --*/
           for( idx = 0; idx < CMDIDX; ++idx ) {
               if( strcmp( cmdtoken, VALIDSYSVIEWCMDS[idx] ) == 0 ) {
                  /*--match with one of allowable commands--*/
                  bVALIDCMD = 1;
                  strcpy(cmdtoken, VALIDSYSVIEWCMDSPATH[idx]);
                  strcpy(actualCMD, cmdtoken);
                  strcat(actualCMD, " ");
                  break;
               }
           }
       } else {
          strcat(actualCMD, token);
          strcat(actualCMD, " ");
       }
       word_count = word_count + 1;
   }    
   /*-- passed in string should contain nodeip
    *   in 1st token and the rest of the line as is --*/
   /*-- posible commands: --*/
   if ( strlen(cmdtoken) > 0) {
       for( idx = 0; idx < 8; ++idx ) {
           if( strcmp( cmdtoken, VALIDSYSVIEWCMDS[idx] ) == 0 ) {
              /*--match with one of allowable commands--*/
               bVALIDCMD = 1;
               strcpy(cmdtoken, VALIDSYSVIEWCMDSPATH[idx]); 
               /** if (strcmp(cmdtoken, "lsof") == 0) **/
                   strcat(actualCMD, " | head -n2000 ");  /*--limit to first 200 lines of output --*/
               break;
           }
       }
   }
   if (strlen(userSelStr) > 0 && bVALIDCMD == 1)
   {
#ifdef M_DEBUG
   printf("nodeip:%s  2ndtoken:%s\n", nodeip, cmdtoken);
   printf("actualCMD:%s\n", actualCMD);
#endif
       child_dig_pid = fork();
       if (child_dig_pid > 0) {
       /* parent process */
       /* output filename to be used in child_dig_pid */
          strcpy(SockDiffOutFName, basedir);
          strcat(SockDiffOutFName, "/tmp/_dockerout_");
          itoa(child_dig_pid, filename, 10);
          strcat(SockDiffOutFName, filename);
          strcpy(filename, SockDiffOutFName);
          waitpid(child_dig_pid, 0, 0); /* wait until child process finished */
          byte_count=1;
          line_count=0;
          rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * TINY_RPYBUFFLEN);
          memset(rpyBuffer->Output, '\0', TINY_RPYBUFFLEN);
          if((fp = fopen(SockDiffOutFName, "r")) != NULL){
              fflush(fp);
              tmpBuffer[2000] = '\0';
              while(fgets(tmpBuffer, sizeof(tmpBuffer), fp)!=NULL){
                  strcat(rpyBuffer->Output, tmpBuffer);
                  line_count++;
                  byte_count=byte_count+ strlen(tmpBuffer);
                  tmpBuffer[2000] = '\0';
              }
              fclose(fp);
          }
          remove(filename);
          replace_str(rpyBuffer->Output, " encoA", "");
          rpyBuffer->RpyEntries = line_count;
          rpyBuffer->RpyBufferLength = byte_count + RPYHEADERLEN + 1;
          rpyBuffer->ReturnCode = 0;
          rpyBuffer->ReasonCode = 0;
          rpyBuffer->ProdCode = PRODUCTCODE;

          rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
          rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
          rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
          rpyBuffer->ProdCode = htonl(PRODUCTCODE);
          rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
          /* debug check on output contents */
#ifdef M_DEBUG
          printf("Replied with %d bytes\nNumber of entries:%d\nHeaderLEN=%d\n", ntohl(rpyBuffer->RpyBufferLength), ntohs(rpyBuffer->RpyEntries), RPYHEADERLEN);
          printf("Contents:\n%s\n", rpyBuffer->Output);
#endif
          /* send output back to sender */
          if(send(listenchannel, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
              perror("send() error!");

          free(rpyBuffer);  /* deallocate memory (this causes the next query to hang...weird! */
      } else if (child_dig_pid == 0) {
          /* construct the command string */
          remoteCmd_t *REMCtrl;
          REMCtrl = (remoteCmd_t *) malloc(sizeof(RpyHeader_t) * 564 );
          /*****
           *-- 1. retrieve mysql table for action_label
           *****/
          /* get authentication info base on NodeIP */
          strcpy(REMCtrl->targetuserid, getDataField(serverIP, nodeip, 2));
          strcpy(REMCtrl->targetpasswd, getDataField(serverIP, nodeip, 3));
          strcpy(REMCtrl->privatekey, getDataField(serverIP, nodeip, 4));
          strcpy(REMCtrl->targetip, nodeip);   /* remote ip address */


#ifdef M_DEBUG
 printf("DEBUG: REMCtrl->targetuserid:%s REMCtrl->targetpasswd:%s REMCtrl->targetip:%s REMCtrl->privatekey:%s\n", REMCtrl->targetuserid, REMCtrl->targetpasswd, REMCtrl->targetip, REMCtrl->privatekey);
#endif
          /* stuff the commandline */
          /* deal with various putty optional command formats */
          if ( strlen(REMCtrl->privatekey) > 1 && strlen(REMCtrl->targetuserid) > 0 ) {
              strcpy(CmdSTRING, "plink ");
              strcat(CmdSTRING, REMCtrl->targetuserid);
              strcat(CmdSTRING, "@");
              strcat(CmdSTRING, REMCtrl->targetip);
              strcat(CmdSTRING, " -i ");  /* option for private key */
              strcat(CmdSTRING, REMCtrl->privatekey);
              strcat(CmdSTRING, " sudo ");
          } else if (strlen(REMCtrl->targetuserid) > 0 && strlen(REMCtrl->targetpasswd) > 0) {
              strcpy(CmdSTRING, "plink ");
              strcat(CmdSTRING, REMCtrl->targetuserid);
              strcat(CmdSTRING, "@");
              strcat(CmdSTRING, REMCtrl->targetip);
              strcat(CmdSTRING, " -pw ");
              strcat(CmdSTRING, REMCtrl->targetpasswd);
              strcat(CmdSTRING, " ");
          } else {
              /* configured authentication is not found */
#ifdef M_DEBUG
          printf("WARNING:  Remote authentication not yet configured.\n");
#endif
          }
#ifdef M_DEBUG
          printf("DEBUG: REMCtrl->targetuserid:%s REMCtrl->targetpasswd:%s REMCtrl->targetip:%s  strlen(pkey):%d \n", REMCtrl->targetuserid, REMCtrl->targetpasswd, REMCtrl->targetip, strlen(REMCtrl->privatekey));
#endif
          //trimse(actualCMD);

          strcat(CmdSTRING, actualCMD);
          strcat(CmdSTRING, " 2>&1 > ");
          /* output filename to be used in child_pid */
          strcpy(SockDiffOutFName, basedir);
          strcat(SockDiffOutFName, "/tmp/_dockerout_");
          itoa(getpid(), filename, 10);
          strcat(SockDiffOutFName, filename);
          strcat(CmdSTRING, SockDiffOutFName);
#ifdef M_DEBUG
          printf("clientCmdString=%s\n", CmdSTRING);
#endif

          execl(SHELL, SHELL, "-c", CmdSTRING, NULL);
          _exit(EXIT_FAILURE);
      }
   }
   return 0;
}




int run_dockerview( int listenchannel, char *userSelStr, char *serverIP, char *basedir)
{
   RpyHeader_t  *rpyBuffer;
   pid_t child_dig_pid;
   char *filename = (char *) malloc (sizeof(char) * 350);
   char *CmdSTRING = (char *) malloc (sizeof(char) * 1024);
   char *DockerOutFName = (char *) malloc (sizeof(char) * 150);
   char tmpBuffer[1024];
   FILE *fp;
   int byte_count, line_count, idx;
   size_t RPYHEADERLEN;
   char *token = (char *) malloc (sizeof(char) * 250);
   const char delim[1] = " ";
   const char *nodeip = (char *) malloc (sizeof(char) * 42);
   const char *cmdtoken = (char *) malloc (sizeof(char) * 10);
   const char *actualCMD = (char *) malloc (sizeof(char) * 218);
   RPYHEADERLEN=14;


   /* expect two or more tokens from userSelStr
    * nodeip = token[0]
    * rest of commandline = token[1..n]
    */
#ifdef M_DEBUG
   printf("userSelStr:%s\n", nodeip, userSelStr);
#endif
   token = strtok(userSelStr, delim);
   strcpy(nodeip, token);
   token = strtok(NULL, delim);
   strcpy(actualCMD, token);
   token = strtok(NULL, delim);
   strcpy(cmdtoken, token);
#ifdef M_DEBUG
   printf("nodeip:%s  2ndtoken:%s\n", nodeip, cmdtoken);
   printf("actualCMD:%s\n", actualCMD);
#endif
   /*-- passed in string should contain nodeip
        in 1st token and the rest of the line as is --*/
   /*-- posible commands: --*/

   if ((strlen(userSelStr) > 0) && (strcmp(cmdtoken, "docker" == 0))) {
       child_dig_pid = fork();

       if (child_dig_pid > 0) {
       /* parent process */
       /* output filename to be used in child_dig_pid */
          strcpy(DockerOutFName, basedir);
          strcat(DockerOutFName, "/tmp/_dockerout_");
          itoa(child_dig_pid, filename, 10);
          strcat(DockerOutFName, filename);
          strcpy(filename, DockerOutFName);
          waitpid(child_dig_pid, 0, 0); /* wait until child process finished */
          byte_count=1;
          line_count=0;
          rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * TINY_RPYBUFFLEN);
          memset(rpyBuffer->Output, '\0', TINY_RPYBUFFLEN);
          if((fp = fopen(DockerOutFName, "r")) != NULL) {
              fflush(fp);
              tmpBuffer[500] = '\0';
              while(fgets(tmpBuffer, sizeof(tmpBuffer), fp)!=NULL)
              {
                  strcat(rpyBuffer->Output, tmpBuffer);
                  line_count++;
                  byte_count=byte_count+ strlen(tmpBuffer);
                  tmpBuffer[500] = '\0';
              }
              fclose(fp);
          }
          remove(filename);
          replace_str(rpyBuffer->Output, " encoA", "");
          rpyBuffer->RpyEntries = line_count;
          rpyBuffer->RpyBufferLength = byte_count + RPYHEADERLEN + 1;
          rpyBuffer->ReturnCode = 0;
          rpyBuffer->ReasonCode = 0;
          rpyBuffer->ProdCode = PRODUCTCODE;
          rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
          rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
          rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
          rpyBuffer->ProdCode = htonl(PRODUCTCODE);
          rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

          /* debug check on output contents */
          printf("Replied with %d bytes\nNumber of entries:%d\nHeaderLEN=%d\n", ntohl(rpyBuffer->RpyBufferLength), ntohs(rpyBuffer->RpyEntries), RPYHEADERLEN);
#ifdef M_DEBUG
          printf("Contents:\n%s\n", rpyBuffer->Output);
#endif
          /* send output back to sender */
          if(send(listenchannel, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
              perror("send() error!");

          free(rpyBuffer);  /* deallocate memory (this causes the next query to hang...weird! */
       } else if (child_dig_pid == 0) {
          /* construct the command string */
          remoteCmd_t *REMCtrl;
          REMCtrl = (remoteCmd_t *) malloc(sizeof(RpyHeader_t) * 564 );
          /*-- 1. retrieve mysql table for action_label --*/
          /* get authentication info base on NodeIP */
          strcpy(REMCtrl->targetuserid, getDataField(serverIP, nodeip, 2));
          strcpy(REMCtrl->targetpasswd, getDataField(serverIP, nodeip, 3));
          strcpy(REMCtrl->privatekey, getDataField(serverIP, nodeip, 4));
          strcpy(REMCtrl->targetip, nodeip);   /* remote ip address */

          /* stuff the commandline */
          /* deal with various putty optional command formats */
          if ( strlen(REMCtrl->privatekey) > 1 && strlen(REMCtrl->targetuserid) > 0 ) {
              strcpy(CmdSTRING, "plink ");
              strcat(CmdSTRING, REMCtrl->targetuserid);
              strcat(CmdSTRING, "@");
              strcat(CmdSTRING, REMCtrl->targetip);
              strcat(CmdSTRING, " -i ");  /* option for private key */
              strcat(CmdSTRING, REMCtrl->privatekey);
              strcat(CmdSTRING, " sudo ");
          } else if (strlen(REMCtrl->targetuserid) > 0 && strlen(REMCtrl->targetpasswd) > 0) {
              strcpy(CmdSTRING, "plink ");
              strcat(CmdSTRING, REMCtrl->targetuserid);
              strcat(CmdSTRING, "@");
              strcat(CmdSTRING, REMCtrl->targetip);
              strcat(CmdSTRING, " -pw ");
              strcat(CmdSTRING, REMCtrl->targetpasswd);
          }

          strcat(CmdSTRING, " ");
          strcat(CmdSTRING, actualCMD);
          strcat(CmdSTRING, " 2>&1 > ");
          /* output filename to be used in child_pid */
          strcpy(DockerOutFName, basedir);
          strcat(DockerOutFName, "/tmp/_dockerout_");
          itoa(getpid(), filename, 10);
          strcat(DockerOutFName, filename);
          strcat(CmdSTRING, DockerOutFName);

#ifdef M_DEBUG
          printf("clientCmdString=%s\n", CmdSTRING);
#endif

          execl(SHELL, SHELL, "-c", CmdSTRING, NULL);
          _exit(EXIT_FAILURE);
      }
   }
   return 0;
}








/*-- access item in database --*/
/*-------------------------------------------------------------------*/
/* get community name from a specified node                          */
/* Where field switch:                                               */
/* 1 == get CommunityName                                            */
/* 2 == get sudoUserID                                               */
/* 3 == get sudoPassword                                             */
/* 4 == get private key file name(fullpath)                          */
/*-------------------------------------------------------------------*/
char *getDataField(char *SVERIP, char *NODEIP, int field)
{
   MYSQL *conn;
   MYSQL_RES *res;
   MYSQL_ROW row;
   int x;
   unsigned int num_cols=0;
   char *server = "137.72.43.204";
   char *user = "clevermonitor";
   char *password = "cleverview7070"; /* set me first */
   char *database = "CV4LINUXMASTER";
   char *sqlstmt = malloc(CNAMESIZE * sizeof(char));
   char *CommunStr = malloc(CNAMESIZE * sizeof(char));
//SELECT NodeIPAddr, SudoUserID, DECODE(SudoPassword,'ernrdhtclm') AS 'SudoPassword', bKVMHost, bDockerHost FROM node_conf WHERE NodeIPAddr=inNodeIP;
   switch (field) {
      case 1:  /* communityname */ 
          strcpy(sqlstmt, "SELECT DECODE(NodeCommunityName, 'ernrdhtclm') FROM node_conf WHERE NodeIPAddr='");
          strcat(sqlstmt, NODEIP);
          strcat(sqlstmt, "';");
      break;
      case 2:  /*'sudoUserID'*/
          strcpy(sqlstmt, "SELECT SudoUserID FROM node_conf WHERE NodeIPAddr='");
          strcat(sqlstmt, NODEIP);
          strcat(sqlstmt, "';");
      break;
      case 3: /*'sudoPassword'*/
          strcpy(sqlstmt, "SELECT DECODE(SudoPassword, 'ernrdhtclm') FROM node_conf WHERE NodeIPAddr='");
          strcat(sqlstmt, NODEIP);
          strcat(sqlstmt, "';");
      break;
      case 4: /*'privateKey'*/
          strcpy(sqlstmt, "SELECT privateKey FROM node_conf WHERE NodeIPAddr='");
          strcat(sqlstmt, NODEIP);
          strcat(sqlstmt, "';");
      break;
   }
   //printf("DEBUG(getDataField): sqlstmt:%s\n", sqlstmt);
   conn = mysql_init(NULL);

   /* Connect to database */
   if (!mysql_real_connect(conn, SVERIP, user, password, database, 0, NULL, 0)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
   }

   /* send an SQL query */
   if (mysql_query(conn, sqlstmt)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
   }

   res = mysql_use_result(conn);
   num_cols = mysql_num_fields(res);

   if ((row = mysql_fetch_row(res)) != NULL)
   {
       /*
       for (x=0; x<num_cols; x++)
       {
          printf("%d -- %s  ", x, row[x]);
       }
       */
       strcpy(CommunStr, row[0]);
   }
   //fprintf(stdout, "DEBUG: CommunityName=%s\n", CommunStr);

   /* close connection */
   mysql_free_result(res);
   mysql_close(conn);
   return CommunStr;
}


/*-- Licensing --*/
static char key[]= "@@CLEVER";
long seed[];
int p[ESIZE], q[ESIZE], s[ESIZE];

int is_valid_ip(const char *ip_str)
{
        unsigned int n1,n2,n3,n4;

        if(sscanf(ip_str,"%u.%u.%u.%u", &n1, &n2, &n3, &n4) != 4) return 0;

        if((n1 != 0) && (n1 <= 255) && (n2 <= 255) && (n3 <= 255) && (n4 <= 255)) {
                char buf[64];
                sprintf(buf,"%u.%u.%u.%u",n1,n2,n3,n4);
                if(strcmp(buf,ip_str)) return 0;
                return 1;
        }
        return 0;
}

size_t get_file_size(char *fname) 
{
    FILE *fp;
    size_t retcode = 0; 
    fp = fopen(fname, "rb");
    if (fp != NULL)
    {
        while(getc(fp) != EOF) retcode++;
    }
    close(fp);
    return retcode;
}


/*-------------------------------------------------------------------*/
/* converts date string to time_t                                    */
/*-------------------------------------------------------------------*/
time_t to_seconds(char *src_date)
{
	char *fmt="%F"; /* yyyy-mm-dd format for date << change as needed */
	struct tm tmp_time;
	if(! *src_date) return 0; /* this means an error */
        //printf("to_seconds-- datestr=%s\n", src_date);
	strptime(src_date, fmt, &tmp_time);
	return mktime(&tmp_time);
}


/*-------------------------------------------------------------------*/
/* replace character in string                                       */
/*-------------------------------------------------------------------*/
char *str_replace ( const char *string, const char *substr, const char *replacement ){
  char *tok = NULL;
  char *newstr = NULL;
  char *oldstr = NULL;
  char *head = NULL;
 
  /* if either substr or replacement is NULL, duplicate string a let caller handle it */
  if ( substr == NULL || replacement == NULL ) return strdup (string);
  newstr = strdup (string);
  head = newstr;
  while ( (tok = strstr ( head, substr ))){
    oldstr = newstr;
    newstr = malloc ( strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) + 1 );
    /*failed to alloc mem, free old string and return NULL */
    if ( newstr == NULL ){
      free (oldstr);
      return NULL;
    }
    memcpy ( newstr, oldstr, tok - oldstr );
    memcpy ( newstr + (tok - oldstr), replacement, strlen ( replacement ) );
    memcpy ( newstr + (tok - oldstr) + strlen( replacement ), tok + strlen ( substr ), strlen ( oldstr ) - strlen ( substr ) - ( tok - oldstr ) );
    memset ( newstr + strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) , 0, 1 );
    /* move back head right after the last replacement */
    head = newstr + (tok - oldstr) + strlen( replacement );
    free (oldstr);
  }
  return newstr;
}




/*-------------------------------------------------------------------*/
/* trim white spaces at start and end of string                      */
/*-------------------------------------------------------------------*/
void trimse(char * str)
{
    int lastSpaceIndex, i;
    lastSpaceIndex = 0;
    while (str[lastSpaceIndex] = ' ' || str[lastSpaceIndex] == '\t' || str[lastSpaceIndex] == '\n')
    {
        lastSpaceIndex++;
    }
    i = 0;
    while (str[i + lastSpaceIndex] != '\0')
    {
        str[i] = str[i + lastSpaceIndex];
        i++;
    }
    str[i] = '\0';
}

char *trim(char *str)
{
    size_t len = 0;
    char *frontp = str - 1;
    char *endp = NULL;

    if( str == NULL )
            return NULL;

    if( str[0] == '\0' )
            return str;

    len = strlen(str);
    endp = str + len;

    /* Move the front and back pointers to address
     * the first non-whitespace characters from
     * each end.
     */
    while( isspace(*(++frontp)) );
    while( isspace(*(--endp)) && endp != frontp );

    if( str + len - 1 != endp )
            *(endp + 1) = '\0';
    else if( frontp != str &&  endp == frontp )
            *str = '\0';

    /* Shift the string so that it starts at str so
     * that if it's dynamically allocated, we can
     * still free it on the returned pointer.  Note
     * the reuse of endp to mean the front of the
     * string buffer now.
     */
    endp = str;
    if( frontp != str )
    {
            while( *frontp ) *endp++ = *frontp++;
            *endp = '\0';
    }
    return str;
}



/*----------------------------------------------------------------------------------------*/
/* parse the date value and determine expiration status by comparing it with current date */
/*----------------------------------------------------------------------------------------*/
int isExpired(char *dateval) {
    time_t currtime, licensedtime, difference;
    struct tm *loctime;
    int year, month, day;
    int currday, curryear, currmonth;
    int licensed_secs;
    struct tm* locptr;

    const char* FMT = "%04d-%02d-%02d";
    licensed_secs = sscanf(dateval, FMT, &year, &month, &day);
    struct tm tmv = { 0, 0, 0, day, month - 1, year - 1900, -1, -1, -1 };
    licensedtime = mktime(&tmv);

    // Current time in broken-down time form
    locptr = ({ time_t curtime = time(NULL); localtime(&curtime); });
    currday = locptr->tm_mday;   // 1st DOW: sun=0 -> sat=6
    currmonth = locptr->tm_mon + 1;
    curryear = locptr->tm_year + 1900;
    currtime = ({ struct tm tmv = mk_tm(curryear, currmonth, currday, 0, 0, 0); mktime(&tmv); });

    difference = licensedtime - currtime;    
    if ( difference < 0)
        return 1;   //expired!!!
    else
        return 0;   //still good.
}






/*----------------------------------------------------------------------------------------*/
/* date string parser                                                                     */ 
/*----------------------------------------------------------------------------------------*/
int* dt_parser(char *dt)
{
    int *ptr;
    int *sam;
    char *temp;
    char *samtemp;
    temp=(char *) malloc(sizeof(char) * 5);
    ptr=(int *) malloc(sizeof(int) * 3);

    for (samtemp=temp, sam=ptr; *dt != NULL; dt++)
    {
        if (*dt != '/')
            *temp++=*dt;
        else {
            *temp='\x0';
            *ptr++=atoi(samtemp);
            samtemp=temp;
        }
    }
    *temp='\x0';
    *ptr++=atoi(samtemp);
    samtemp=temp;
    *ptr=-1;
    return sam;
}


/*-------------------------------------------------------------------*/
/* determine if the checksum fans out okay                           */ 
/* 1=invalid, 0=valid                                                */
/*-------------------------------------------------------------------*/
int isValidChksum(char optionval[], long validVal) {
    long xval=0;
    int i, integral;
    int len=strlen(optionval);
    for (i=0; i<len; i++) { 
       integral = optionval[i];
       if (integral < 0) integral *= -1;
       xval += integral;
    }

    xval = xval * 314;

    if (xval == validVal) 
       return 0;
    else
       return 1;
    return 0;
}


/*-------------------------------------------------------------------*/
/* generate a random integer                                         */ 
/*-------------------------------------------------------------------*/
int getRandInt() {
    int a; 
    int index;
    srand((unsigned) time(0));
    int retval=0;
    int lowest=1;
    int highest=10000; 
    int range=(highest-lowest) + 1;
    for (index=1; index<3; index++) {
        a = lowest + (int)(range*rand() / (RAND_MAX + 1.0));
        if (index == 1) retval = a;
        //printf("FROM getRandInt-- idx:%d value:%d\n", index, a);
    }
    return retval;   
}


/*-------------------------------------------------------------------*/
/*	To convert 53 to the character 'S':                          */
/*	char returnVal = hexToString('5', '3');                      */
/*-------------------------------------------------------------------*/
char hexToAscii(char first, char second)
{
	char hex[5], *stop;
	hex[0] = '0';
	hex[1] = 'x';
	hex[2] = first;
	hex[3] = second;
	hex[4] = 0;
	return strtol(hex, &stop, 16);
}


/*-------------------------------------------------------------------*/
/* determine if character is numeric                                 */ 
/*-------------------------------------------------------------------*/
int is_numeric(const char *p) {
     if (*p) {
          char c;
          while ((c=*p++)) {
                if (!isdigit(c)) return 0;
          }
          return 1;
      }
      return 0;
}


/*-------------------------------------------------------------------*/
/* encrypt a string                                                  */ 
/*-------------------------------------------------------------------*/
//void aescrypt(ins, outs, len)
//char ins[];
//char outs[];
//int len;
void aescrypt(char ins[], char outs[], int len)
{
  int  i,c,r0,r1,r2,keylen=8;
  seed[0] = seed[1] = seed[2] = 0x0;

  /*
   * forms the seeds: 1st 4, last 4 and middle 4 chars of the key
   */
  for (i=0; i<4; i++) {
    seed[0] = seed[0] << 8 | key[i];
    seed[1] = seed[1] << 8 | key[keylen-1-i];
    seed[2] = seed[2] << 8 | key[keylen/2+i-2];
  }

  for (i=0; i<ESIZE; i++)
    p[i] = i;

  shuffle(p, ESIZE, 0);

  for (i=0; i<NDELAY; i++) {
    shuffle(p, ESIZE, 379);
    shuffle(p, ESIZE, 421);
    shuffle(p, ESIZE, 539);
  }

  for (i=0; i<ESIZE; i+=2)                       /* self-inverse      */
    s[ s[ p[i]] = p[i+1] ] = p[i];

  shuffle(p, ESIZE, 1);

  for (i=0; i<ESIZE; i++)                        /* p = inverse of q  */
    q[p[i]] = i;

  for (i=0; i<len; i++)
  {
    c = *ins++;
    //c = ins[i];
    r0 = rand8(0);
    r1 = rand8(1);
    r2 = rand8(2);
    c  = (c ^ r2) + r0;
    c  = q[BYTE(s[BYTE(p[BYTE(c)] + r1)] - r1)];

    c  = (c - r0) ^ r2;
    *outs++ = c;
  }
  *outs-- = 0;
  
}


/*-------------------------------------------------------------------*/
/* Prepend a character '0' to the existing string                    */
/*-------------------------------------------------------------------*/
char *strrev(char *s){
    char *p=s;
    char *q =s;
    char swap;
    if (*s)
    {
        q=strchr(q,'\0');
        while (--q > p)
        {
            swap = *q;
            *q = *p;
            *p = swap;
            ++p;
        }
    }
    return s;
}

/*-------------------------------------------------------------------*/
/* string to upper case                                              */
/*-------------------------------------------------------------------*/
void stoupper(char *s)
{
    for(; *s; s++)
       if(('a' <= *s) && (*s <= 'z'))
          *s = 'A' + (*s - 'a');
}



/*-------------------------------------------------------------------*/
/* randomly shuffles an array                                        */
/* void shuffle(a, size, rstream)                                    */
/*-------------------------------------------------------------------*/
void shuffle(int a[], int size, int rstream)
{
    register int i, j, temp;

    for (i=size-1; i>=0; i--) {
        j = rand8(rstream) % (i+1);
        if ( i > 0 ) {
            temp = a[i];    
            a[i]= a[j]; 
            a[j] = temp;
        }
    }
}



/*-------------------------------------------------------------------*/
/* returns a psedorandom byte from one of serveral streams           */
/*-------------------------------------------------------------------*/
int rand8(int i)
{
    int retval=0;
    while (retval < 0 ) {
        seed[i] = seed[i] * 1000625439L + 84984;
        retval = (BYTE(seed[i] >> 19));
    }
    return retval;
}




/*-------------------------------------------------------------------*/
/* return 0=equal 1=greater -1=lesser                                */
/*-------------------------------------------------------------------*/
int greater(time_t a, time_t b)
{
	if(a>b) return 1;
	if(a<b) return (-1);
	return 0;
}

/*-------------------------------------------------------------------*/
/* parses and validates decrypted license components                 */
/*-------------------------------------------------------------------*/
int comparetokens(Lic_t *CocoPop) {
    int j;
    char TRIALVAL[2];
    char *host_idchar;
    time_t nowTime;

    char *str1, *token;
    char *saveptr1;
    int caledexp;
    char *EXP_M;
    char *EXP_D;
    char *EXP_Y;
    char *expirationstr;
    char *M_EXP_M;
    char *M_EXP_D;
    char *M_EXP_Y;
 
    //printf("Local HostID:%lX\n", gethostid());

    token = (char *) malloc(sizeof(char) * 250);
    EXP_M = (char *) malloc(sizeof(char) * 3);
    EXP_D = (char *) malloc(sizeof(char) * 3);
    EXP_Y = (char *) malloc(sizeof(char) * 5);
    M_EXP_M = (char *) malloc(sizeof(char) * 3);
    M_EXP_D = (char *) malloc(sizeof(char) * 3);
    M_EXP_Y = (char *) malloc(sizeof(char) * 5);
    nowTime = time(NULL);

//    printf("DEBUG-- unoptioned:%s\n", CocoPop->unoption);

    for (j = 1, str1 = CocoPop->unoption; ; j++, str1 = NULL) {
        token = strtok_r(str1, " ", &saveptr1);
        if (token == NULL)
            break;
        //printf("Index:%d   Token:%s\n", j, token); 

        /*-- Are the values matched with the option? --*/
        /*-- Expected output as AAA hostid exp_month exp_day exp_year nodes users holder1 mobile_option m_exp_month m_exp_day m_exp_year sysview_option ... --*/
        /*--       1      2    3  4   5   6  7  8 9    10 11 12   13 --*/
        /*-- eg.  AAA 48899F2B 12 27 2013 14 23 0 True 12 25 2013 True --*/
        switch (j) {
            case 1: /*-- product designation --*/
                 if (strncmp(token, "AAA", 3) != 0) {
                     printf("Invalid license.  Current license is not intended for CleverView for TCP/IP on linux.\nProgram terminated.\n");
                     return 1;  /*-- exit run-time --*/
                 }
                 break;
            case 2: /*-- hostid --*/
                 /*-- convert hostid from long to string --*/ 
                 host_idchar = (char *) malloc(sizeof(char) * 20);
                 //sprintf(host_idchar, "%.2X", host_id);
                 sprintf(host_idchar, "%2X", gethostid());
                 stoupper(host_idchar);
                 stoupper(token);
                 stoupper(CocoPop->hostid);
                 //printf("DEBUG-- host_idchar:%s token:%s Cocopop-hostid:%s\n", host_idchar, token, CocoPop->hostid);
                 if ( strlen(host_idchar) < 8 ) {
                     //printf("DEBUG-- hostid len is less than 8, it is %i\n", strlen(host_idchar));

                     while(strlen(host_idchar) < 8)
                     {
                      strcpy(host_idchar, strrev(host_idchar));
                      strcat(host_idchar, "0");
                      strcpy(host_idchar, strrev(host_idchar));
                     }
                     //printf("Now hostid is %s\n", host_idchar);
                 }

                 if (memcmp(CocoPop->hostid, "0XFFFFFFFF", 10) == 0) {
                     printf("Current limited trial license is for prospective customers.\n");
                 } else if (memcmp(token, host_idchar, strlen(token)) != 0) {
                     printf("Invalid license.  Current license is not intended for this host.\nYour current hostid:%s Intended license is for hostid:%s\nProgram terminated.\n", host_idchar, token);
                     return 1;  /*-- exit run-time --*/
                 }
                 break;
            case 3:
                 /*-- exp_month --*/
                 strcpy(EXP_M, token);
                 break;
            case 4:
                 /*-- exp_day --*/
                 strcpy(EXP_D, token);
                 break;
            case 5:
                 /*-- exp_year --*/
                 strcpy(EXP_Y, token);

                 /*-- exp_month, exp_day, exp_year --*/
                 expirationstr = (char *) malloc(sizeof(char) * 11);
                 strcpy(expirationstr, EXP_Y);
                 strcat(expirationstr, "-");
                 strcat(expirationstr, EXP_M);
                 strcat(expirationstr, "-");
                 strcat(expirationstr, EXP_D);
                 //printf("DEBUG-- expiration date:%s\n", expirationstr);
                 if (memcmp(expirationstr, "2038-01-01", strlen("2038-01-01")) == 0) {
                     CocoPop->isTrial = 0;
                     strcpy(TRIALVAL, "0");
                 } else { 
                     if ((memcmp(token, "None", strlen("None")) != 0) && (strlen(token) > 0)) {
                         CocoPop->isTrial = 1;
                         strcpy(TRIALVAL, "1");
                         caledexp=0;
                         /*-- parse expiration date --*/
                         caledexp=isExpired(expirationstr);
                         if (caledexp == 1) {
                             printf("Current term limit license has expired.  Please contact support via phone 1-650-617-2400 or email support@aesclever.com for further assistance.\n");
                             return 1;  /*-- exit run-time --*/
                         } else {
                             printf("This monitor is running under a term limit license which would be expired by %s-%s-%s\n", EXP_M, EXP_D, EXP_Y);
                         } 
                     }
                 }
                 break;
            case 6: /*-- nodes --*/
                 //printf("DEBUG-- MaxNodes:%s Token:%s\n", CocoPop->maxnodes, token);
                 if (memcmp(token, CocoPop->maxnodes, strlen(CocoPop->maxnodes)) != 0) {
                     printf("Invalid license. token:%s maxnode:%d Number of licensed nodes has been corrupted.\nProgram terminated.", token, CocoPop->maxnodes);
                     return 1;  /*-- exit run-time --*/
                 }
                 break;
            case 7: /*-- user accounts --*/
                 //printf("MaxUser:%s Token:%s\n", CocoPop->maxusers, token);
                 if (memcmp(token, CocoPop->maxusers, strlen(CocoPop->maxusers)) != 0) {
                     printf("Invalid license.  Number of licensed accounts has been corrupted.\nProgram terminated.");
                     return 1;  /*-- exit run-time --*/
                 }
                 break;
            case 9: /*-- mobile option: true/false --*/
                 //printf("Mobile option? Token:%s\n", token);
                 if (strlen(token) > 0) {
                    if (memcmp(token, CocoPop->mobile, strlen(CocoPop->mobile)) != 0) {
                        if (memcmp(token, "True", strlen("True")) == 0) {
                            printf("Mobile option is also licensed ");
                        } else {
                            printf("Mobile option is not licensed ");
                        }
                    }
                 //printf("Mobile option:%s Token:%s\n", CocoPop->mobile, token);
                 }
                 break;
            case 10:
                 /*-- mobile_exp_month --*/
                 strcpy(M_EXP_M, token);
                 break;
            case 11:
                 /*-- mobile_exp_day --*/
                 strcpy(M_EXP_D, token);
                 break;
            case 12:
                 /*-- mobile_exp_year --*/
                 strcpy(M_EXP_Y, token);
                 printf(" and will be expired by %s-%s-%s\n", M_EXP_M, M_EXP_D, M_EXP_Y);
                 break;            
            case 13:
                 //printf("SysView:%s Token:%s\n", CocoPop->sysview, token);
                 /*-- sysview option: true/false --*/
                 if (strlen(token) > 0) {
                    if (memcmp(token, CocoPop->sysview, strlen(CocoPop->sysview)) != 0) {
                        if (memcmp(token, "True", strlen("True")) == 0) {
                            printf("SysView option is also licensed.");
                        } else {
                            printf("SysView option is not licensed.");
                        }
                    }
                 }
                 break;
            case 14:
                 //printf("BlockChainView:%s Token:%s\n", CocoPop->blockchainview, token);
                 /*-- blockchainview option: true/false --*/
                 if (strlen(token) > 0) {
                    if (memcmp(token, CocoPop->blockchainview, strlen(CocoPop->blockchainview)) != 0) {
                        if (memcmp(token, "True", strlen("True")) == 0) {
                            printf("\nBlockChainView option is also licensed.");
                        } else {
                            printf("BlockChainView option is not licensed.");
                        }
                    }
                 }
                 break;
            default:
                 break;
        }

    }
    printf("\n");
    return 0;
}


int validatelicense(char *myLocalIP) 
{
    /*-- MySQL stuff --*/
    mySqlCmd_t *mysqlCommand; 
/*
    MYSQL *conn;
    MYSQL_RES *res;
*/
    /*---------------------------*/
    /*-- Licensing stuff       --*/
    /*---------------------------*/
    Lic_t *CocoPop;
    char *tok=NULL;
    char *strarray[200];
    char testin[200], tmpin[200];
    int firstchar, secondchar;
    int lineidx=0; 
    struct stat licfile;
    int len=0;
    long host_id=gethostid();
    char *host_idchar;
    char *tempstr;
    char TRIALVAL[2];
    char CmdSTRING[1024];
    int i, j, n, bFOUNDADDRES;
    FILE *fp;
    int RETCODE;
    time_t startTime;
    FILE *my_stream;
    char *TOPDIR;
    startTime = time(NULL);
    RETCODE=0;
    bFOUNDADDRES=0;
    char *shcmdstr = (char *) malloc (80);

    /*-- BEGIN --*/
    TOPDIR = (char *) malloc(sizeof(char) * 120);  /* Number of characters in $INSTALLDIR.  Hope this would be log enough... */

    /* get location of license.txt */
    my_stream = fopen ("/etc/cv4env.conf", "r");
    if (my_stream == NULL)
    {
       /* assume TOPDIR is /opt/aes/cv4linux */
       strcpy(TOPDIR, LIC_FILENAME);
    }
    else
    {
        fscanf(my_stream, "%s", TOPDIR);
        /* Close stream; skip error-checking for brevity of example */
        fclose (my_stream);
        strcat(TOPDIR, "/license.txt");
        //printf ("DEBUG-- Top dir is %s\n", TOPDIR);
    }

    /*  Contents of license.txt
USERS=12
NODES=41
HOSTID=0x4889882b
EXPIRATION=0x5880804d00
MOBILE=True
MOBILE_EXPIRATION=0x587745CD
SYSVIEW=True
BLOCKCHAIN=True
OPTION=0x4242421F3337373A373731611F2F321F323A1F312F32381F32311F33321F537176661F2F32
OPCODE=0x1314718
    */

    /*-- initialize mysqlCmd structure --*/
    mysqlCommand = (mySqlCmd_t *) malloc(sizeof(mySqlCmd_t) * 1024);

    strcpy(mysqlCommand->monitorip, myLocalIP);

    /*-- Check for valid license --*/
    //if (stat(LIC_FILENAME, &licfile) == 0) {
    if (stat(TOPDIR, &licfile) == 0) {
        CocoPop = (Lic_t *) malloc(sizeof(Lic_t) * 1024);
        tok = (char *) malloc(sizeof(char) * 200);
        tempstr = (char *) malloc(sizeof(char) * 200);
        lineidx=0;
        //if ((fp=fopen(LIC_FILENAME, "rt")) != NULL) {
        if ((fp=fopen(TOPDIR, "rt")) != NULL) {
           while (fscanf(fp, "%s", tok) != EOF)
           {
               strarray[lineidx] = (char *) malloc(sizeof(char) * 256);
               strcpy(strarray[lineidx], tok);  
               lineidx++;
           }
           fclose(fp);    
           n = lineidx;
           for (i=0; i<lineidx; i++) 
           {
               tok = strtok(strarray[i], "=");
               if (strncmp(tok, "EXPIRATION", 10) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->expiration, tok);
               }
               if (strncmp(tok, "MOBILE_EXPIRATION", 17) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->mobile_expiration, tok);
               }
               if (strncmp(tok, "USERS", 5) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->maxusers, tok);
               }
               if (strncmp(tok, "NODES", 5) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->maxnodes, tok);
               }
               if (strncmp(tok, "MOBILE", 6) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->mobile, tok);
               }
               if (strncmp(tok, "SYSVIEW", 7) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->sysview, tok);
               }
               if (strncmp(tok, "BLOCKCHAIN", 10) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->blockchainview, tok);
               }
               if (strncmp(tok, "HOSTID", 6) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->hostid, tok);
               }
               if (strncmp(tok, "OPTION", 6) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->option, tok);
               }
               if (strncmp(tok, "OPCODE", 6) == 0) {
                   tok = strtok(NULL, ""); 
                   strcpy(CocoPop->opcode, tok);
               }
               if (strncmp(tok, "LICENSE_TO", 10) == 0) {
                   tok = strtok(NULL, "="); 
                   strcpy(CocoPop->companyname, tok);
               }
               if (strncmp(tok, "ADDRESS", 7) == 0) {
                   tok = strtok(NULL, "="); 
                   //strcpy(CocoPop->shippingaddress, tok);
                   bFOUNDADDRES=1;
               }
               if (bFOUNDADDRES == 1) {
                   strcat(CocoPop->shippingaddress, " ");
                   strcat(CocoPop->shippingaddress, tok);
               }
           }
           stoupper(CocoPop->mobile);
           if (strcmp(CocoPop->mobile, "NULL") == 0) {
                strcpy(CocoPop->mobile, "False");
           }
           stoupper(CocoPop->sysview);
           if (strcmp(CocoPop->sysview, "NULL") == 0) {
                strcpy(CocoPop->sysview, "False");
           }
           stoupper(CocoPop->blockchainview);
           if (strcmp(CocoPop->blockchainview, "NULL") == 0) {
                strcpy(CocoPop->blockchainview, "False");
           }
/*
           printf("DEBUG--\nUSERS:%s\n", CocoPop->maxusers);
           printf("NODES:%s\n", CocoPop->maxnodes);
           printf("EXPDATE:%s\n", CocoPop->expiration);
           printf("MOBILE_EXPDATE:%s\n", CocoPop->mobile_expiration);
           printf("HOSTID:%s\n", CocoPop->hostid);
           printf("MOBILE:%s\n", CocoPop->mobile);
           printf("SYSVIEW:%s\n", CocoPop->sysview);
           printf("BLOCKCHAINVIEW:%s\n", CocoPop->blockchainview);
           printf("BLOCKCHAINVIEW:%s\n", CocoPop->iblockchainview);
           printf("OPTION:%s\n", CocoPop->option);
           printf("OPCODE:%s\n", CocoPop->opcode);
           printf("COMAPNY:%s\n", CocoPop->companyname);
           printf("ADDRESS:%s\n", CocoPop->shippingaddress);
*/
        } else {
            /*-- license file not found --*/
            fclose(fp);
            fprintf(stdout, "Error -- Monitor does not have a valid license.  %s is not found.  Please contact support@aesclever.com with your hostid.\n", TOPDIR);

            /* update database */
            memset(CmdSTRING, '\0', sizeof(1024));
            strcpy(CmdSTRING, "UPDATE sql_core_os SET MaXuSerAccTs=0, ProdKeyCurr='15-DAYS-TRIAL-KEY';");
            strcpy(mysqlCommand->sqlcmdstmt, CmdSTRING);
            if (mySQLexec(mysqlCommand) == 1) {   /*-- send sqlstmt to database --*/
                printf("Error updating database.  Please make sure mysql service is active.\n");
            }

            memset(CmdSTRING, '\0', sizeof(1024));
            strcpy(CmdSTRING, "UPDATE sql_kernel_oper_depth SET MaXuSerAccTs=0, bLicense=0, EncryptedProdKey=ENCODE('15-DAYS-TRIAL-KEY', 'ernrdhtclm');");
            strcpy(mysqlCommand->sqlcmdstmt, CmdSTRING);
            if (mySQLexec(mysqlCommand) == 1) {   /*-- send sqlstmt to database --*/
                printf("Error updating database.  Please make sure mysql service is active.\n");
            }

            RETCODE=1;
            return RETCODE;  /*-- exit run-time --*/
        }
    } else {
        fprintf(stdout, "Error -- Monitor does not have a valid license.  %s is not found.  Please contact support@aesclever.com with your hostid.\n", TOPDIR);
        /* update database */
        memset(CmdSTRING, '\0', sizeof(524));
        strcpy(CmdSTRING, "UPDATE sql_core_os SET MaXuSerAccTs=0, ProdKeyCurr='15-DAYS-TRIAL-KEY';");
        strcpy(mysqlCommand->sqlcmdstmt, CmdSTRING);
        if (mySQLexec(mysqlCommand) == 1) {   /*-- send sqlstmt to database --*/
            printf("Error updating database.  Please make sure mysql service is active.\n");
        }

        memset(CmdSTRING, '\0', sizeof(524));
        strcpy(CmdSTRING, "UPDATE sql_kernel_oper_depth SET MaXuSerAccTs=0, bLicense=0, EncryptedProdKey=ENCODE('15-DAYS-TRIAL-KEY', 'ernrdhtclm');");
        strcpy(mysqlCommand->sqlcmdstmt, CmdSTRING);
        if (mySQLexec(mysqlCommand) == 1) {   /*-- send sqlstmt to database --*/
            printf("Error updating database.  Please make sure mysql service is active.\n");
        }
        RETCODE=1;
        return RETCODE;  /*-- exit run-time --*/
    }



    /*-- Validate license --*/
    /*
     * 1. Validate checksum
     */
    if (isValidChksum(CocoPop->option, atol(CocoPop->opcode)) == 0) {
       /* print and log this error */
       fprintf(stdout, "Error -- Monitor does not have a valid license or license has been corrupted.\n" );
       RETCODE=1;
       return RETCODE;
    }
    

    /*-- Matching up license values --*/
    /*-- Is it a term limit license?     --*/
    if (memcmp(CocoPop->expiration, "None", strlen("None")) == 0) { 
        printf("This monitor is running under a perpetual license.\n");
        strcpy(CocoPop->expiration, "0x7fe8964d");
    } else {
        if (memcmp(CocoPop->expiration, "0x7fe8964d", strlen("0x7fe8964d")) == 0) {
            printf("This monitor is running under a perpetual license.\n");
        }
        if (memcmp(CocoPop->expiration, "0xffffffff", strlen("0xffffffff")) == 0) {
            printf("This monitor is running under a perpetual license.\n");
            strcpy(CocoPop->expiration, "0x7fe8964d");
        }
        //strcpy(shcmdstr, "date --date @$(printf '%d\n' ");
        //strcat(shcmdstr, CocoPop->expiration);
        //strcat(shcmdstr, ") '+%Y-%m-%d' > /tmp/dout.txt 2>&1");

        //printf("This monitor is running under a term limit license which would be expired by ");
        //execl(SHELL, SHELL, "-c", shcmdstr, NULL);
        //printf("\n");
    } 

    strcpy (testin, CocoPop->option);
    len = strlen(testin);

    /*-- Convert input hex into chars --*/
    j=0;
    for (i=2; i<len; i+=2) {    /*-- Start at index 2 to skip the first 2 character '0x' --*/
        firstchar=testin[i];
        secondchar=testin[i+1];
        tmpin[j] = hexToAscii(firstchar, secondchar);
        j++;
    }
    len = j;
    /*-- decrypt license string --*/
    aescrypt(tmpin, CocoPop->unoption, len);   


    /*-- Are the embeded values matched with the option? --*/
    if (strlen(CocoPop->unoption) > 0) {
        if (comparetokens(CocoPop) == 1)    
            //return 1;
            RETCODE=1;
    }
    else  /*-- decrypted to zero length string --*/
        //return 1;
        RETCODE=1;

    /*-- Update license settings to database --*/
    memset(CmdSTRING, '\0', sizeof(1024));

    strcpy(CmdSTRING, "UPDATE sql_core_os SET MaXuSerAccts=");
    strcat(CmdSTRING, CocoPop->maxusers);
    strcat(CmdSTRING, ", MaxNodes=");
    strcat(CmdSTRING, CocoPop->maxnodes);
    strcat(CmdSTRING, ", LicensedMobile=ENCODE('");
    strcat(CmdSTRING, CocoPop->mobile);
    strcat(CmdSTRING, "', 'ernrdhtclm')");
    strcat(CmdSTRING, ", bMobileAllowed='");
    strcat(CmdSTRING, CocoPop->mobile);
    strcat(CmdSTRING, "', LicensedSysView=ENCODE('");
    strcat(CmdSTRING, CocoPop->sysview);
    strcat(CmdSTRING, "', 'ernrdhtclm')");
    strcat(CmdSTRING, ", bSysViewAllowed='");
    strcat(CmdSTRING, CocoPop->sysview);
    strcat(CmdSTRING, "', LicensedBChainView=ENCODE('");
    strcat(CmdSTRING, CocoPop->blockchainview);
    strcat(CmdSTRING, "', 'ernrdhtclm')");
    strcat(CmdSTRING, ", bBChainViewAllowed='");
    strcat(CmdSTRING, CocoPop->blockchainview);
    strcat(CmdSTRING, "', S_exp_epo='");
    strcat(CmdSTRING, CocoPop->expiration);
    strcat(CmdSTRING, "', M_exp_epo='");
    strcat(CmdSTRING, CocoPop->mobile_expiration);
    strcat(CmdSTRING, "', ProdKeyCurr='");
    strcat(CmdSTRING, CocoPop->option);
    strcat(CmdSTRING, "', securitystr='");
    strcat(CmdSTRING, CocoPop->opcode);
    if (memcmp(CocoPop->expiration, "None", strlen("None")) == 0) {
        strcpy(TRIALVAL, "0");
        strcat(CmdSTRING, "', bTrial=");
        strcat(CmdSTRING, TRIALVAL);
        strcat(CmdSTRING, ", mobile_expiration=");
        strcat(CmdSTRING, "FROM_UNIXTIME(");
        strcat(CmdSTRING, CocoPop->mobile_expiration);
        strcat(CmdSTRING, ", '%Y-%m-%d')");
        strcat(CmdSTRING, ", Expiration='2037-01-01';");
    } else {
        strcpy(TRIALVAL, "1");
        strcat(CmdSTRING, "', bTrial=");
        strcat(CmdSTRING, TRIALVAL);
        strcat(CmdSTRING, ", mobile_expiration=");
        strcat(CmdSTRING, "FROM_UNIXTIME(");
        strcat(CmdSTRING, CocoPop->mobile_expiration);
        strcat(CmdSTRING, ", '%Y-%m-%d')");
        strcat(CmdSTRING, ", Expiration=FROM_UNIXTIME(");
        strcat(CmdSTRING, CocoPop->expiration);
        strcat(CmdSTRING, ", '%Y-%m-%d');");
    }

    strcpy(mysqlCommand->sqlcmdstmt, CmdSTRING);
    if (mySQLexec(mysqlCommand) == 1) {   /*-- send sqlstmt to database --*/
        printf("Error updating database.  Please make sure mysql service is active.\n");
        RETCODE=1;
        return RETCODE;
    }
    memset(CmdSTRING, '\0', sizeof(1024));
    strcpy(CmdSTRING, "UPDATE sql_kernel_oper_depth SET MaXuSerAccts=");
    strcat(CmdSTRING, CocoPop->maxusers);
    strcat(CmdSTRING, ", MaxNodes=");
    strcat(CmdSTRING, CocoPop->maxnodes);
    strcat(CmdSTRING, ", EncryptedProdKey=ENCODE('");
    strcat(CmdSTRING, CocoPop->option);
    strcat(CmdSTRING, "', 'ernrdhtclm'), bLicense=1, LicensedMobile=ENCODE('");
    strcat(CmdSTRING, CocoPop->mobile);
    strcat(CmdSTRING, "', 'ernrdhtclm')");
    strcat(CmdSTRING, ", LicensedSysView=ENCODE('");
    strcat(CmdSTRING, CocoPop->sysview);
    strcat(CmdSTRING, "', 'ernrdhtclm')");
    strcat(CmdSTRING, ", LicensedBChainView=ENCODE('");
    strcat(CmdSTRING, CocoPop->blockchainview);
    strcat(CmdSTRING, "', 'ernrdhtclm')");
    strcat(CmdSTRING, ", S_exp_epo=AES_ENCRYPT(");
    strcat(CmdSTRING, CocoPop->expiration);
    strcat(CmdSTRING, ", 'ernrdhtclm'), M_exp_epo=AES_ENCRYPT(");
    strcat(CmdSTRING, CocoPop->mobile_expiration);
    strcat(CmdSTRING, ", 'ernrdhtclm')");
    if (memcmp(CocoPop->expiration, "None", strlen("None")) == 0) {
        strcat(CmdSTRING, ", mobile_expiration=ENCODE('");
        strcat(CmdSTRING, CocoPop->mobile_expiration);
        strcat(CmdSTRING, "', 'ernrdhtclm')");
        strcat(CmdSTRING, ", Expiration='2037-01-01';");
    } else {
        strcat(CmdSTRING, ", mobile_expiration=ENCODE('");
        strcat(CmdSTRING, CocoPop->mobile_expiration);
        strcat(CmdSTRING, "', 'ernrdhtclm'), Expiration=FROM_UNIXTIME(");
        strcat(CmdSTRING, CocoPop->expiration);
        strcat(CmdSTRING, ", '%Y-%m-%d');");
    }

    //printf("DEBUGsql_kernel_oper_depth--\n%s\n", CmdSTRING);
    
    strcpy(mysqlCommand->sqlcmdstmt, CmdSTRING);
    mySQLexec(mysqlCommand);   /*-- send sqlstmt to database --*/
    if (mySQLexec(mysqlCommand) == 1) {   /*-- send sqlstmt to database --*/
        printf("Error updating database.  Please make sure mysql service is active.\n");
        RETCODE=1;
        return RETCODE;
    } 

    //printf("Congrats! License checking is done.\n\n");
    return RETCODE;
}

/*-------------------------------------------------------------------*/
/* returns number of lines                                           */
/*-------------------------------------------------------------------*/
int linecount(fp, maxoffs)
FILE *fp;
off_t maxoffs;
{
    off_t       curpos, chc;
    register int        nlines = 0;
    register int        c;

    if (fp == (FILE *)NULL)
        return(0);
    curpos = ftell(fp);
    chc = maxoffs - curpos;
    while ((c = getc(fp)) != EOF && (maxoffs == 0 || chc-- > 0))
        if (c == '\n')
            nlines++;
    (void) fseek(fp, (off_t)curpos, SEEK_SET);
    return(nlines);
}


/*-------------------------------------------------------------------*/
/* Write messages from stdout and stderr to LOG_FILE                 */
/*-------------------------------------------------------------------*/
void log_message(char *filename, char *message) {
     FILE *logfile;
     logfile=fopen(filename, "a");
     if (!logfile) return;
     fprintf(logfile, "%s\n", message);
     fclose(logfile);
}
char *IntToStr( char *str, int num) { sprintf(str, "%d", num); }
char *StrConcat( char *str1, char *str2) { sprintf(str1, "%s", str2); }


char * gnu_getcwd ()
{
    size_t size = 100;
    while (1)
    {
        char *buffer = (char *) malloc (size);
        if (getcwd (buffer, size) == buffer)
            return buffer;
        free (buffer);
        if (errno != ERANGE)
           return 0;
        size *= 2;
    }
}


/*--------------------------------------------------------------------*/
/* reads contents of sepcified file into the outBuffer                */
/* return the number of bytes contain in the outBuffer                */
/*--------------------------------------------------------------------*/
int getOutputFromFile(char *filename, char outBuffer[MAXRPYBYTES]) {
    size_t totbytes;
    FILE *fp; 
    //fprintf(stderr, "Filename: %s\n", filename);
    if ((fp=fopen(filename, "rb")) == NULL)
    {
        fprintf(stderr, "Empty output\n");
        return 0;
    }

    totbytes=fread(outBuffer, 1, MAXRPYBYTES, fp);
    if(totbytes <= 0)
    {
        fprintf(stderr, "Still Empty output\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    //fprintf(stderr, "Output contains %d bytes.\n", totbytes);

    return totbytes;
}


/*---------------------------------------------------------------------------------*/
/* Execute monitoring script(s)                                                    */
/* Scripts are deployed as excutable scripts with appropriate permissions          */
/* Source /opt/aes/cv4linux/cv4*                                                   */
/* Logs are piped to /var/log/cv4log/monitor.log                                   */
/*---------------------------------------------------------------------------------*/
void runMonitoringScript(int scriptnum) 
{
   switch (scriptnum)
   {
       case 1:  /* critical resource */
          fprintf(stdout, "Critical resources monitoring started.\n");
#ifdef LOG
          //system(".cv4CRES > /var/log/cv4log/CritRes.log &");
          if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r cres > /var/log/cv4log/CritRes.log 2>&1", NULL) == -1) {
              fprintf(stderr,"execl Error!");
          }
#else
          if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r cres 2>&1", NULL) == -1) {
              fprintf(stderr,"execl Error!");
          }
#endif
          break;
       case 2: /* port */
          fprintf(stdout, "Port monitoring started.\n");
#ifdef LOG
          //system(".cv4PORT > /var/log/cv4log/PortMon.log &");
          if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r port > /var/log/cv4log/PortMon.log 2>&1", NULL) == -1) {
              fprintf(stderr,"execl Error!");
          }
#else
          if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r port 2>&1", NULL) == -1) {
              fprintf(stderr,"execl Error!");
          }
#endif
          break;
       case 3: /* node monitoring */
          fprintf(stdout, "Node protocol monitoring started.\n");
#ifdef LOG
          //system(".cv4ICMPv4 > /var/log/cv4log/ICMPv4Mon.log &");
          if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r node > /var/log/cv4log/monitor.log 2>&1", NULL) == -1) {
              fprintf(stderr,"execl Error!");
          }
#else
          if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r node &", NULL) == -1) {
              fprintf(stderr,"execl Error!");
          }
#endif
          break;
   }
}


/*---------------------------------------------------------------------------------*/
/* This allows for bidirectional communication with the application being executed */
/*---------------------------------------------------------------------------------*/
pid_t run_popen(const char *command, int *infp, int *outfp)
{
    int p_stdin[2], p_stdout[2];
    pid_t pid;

    if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
        return -1;

    pid = fork();

    if (pid < 0)
        return pid;
    else if (pid == 0)
    {
        close(p_stdin[WRITE]);
        dup2(p_stdin[READ], READ);
        close(p_stdout[READ]);
        dup2(p_stdout[WRITE], WRITE);

        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("execl");
        exit(1);
    }

    if (infp == NULL)
        close(p_stdin[WRITE]);
    else
        *infp = p_stdin[WRITE];

    if (outfp == NULL)
        close(p_stdout[READ]);
    else
        *outfp = p_stdout[READ];

    return pid;
}

int aesstrcmp(const char *s1, const char *s2)
{
    while((*s1 && *s2) && (*s1++ == *s2++));
    return *(--s1) - *(--s2);
}


/*-----------------------------*/
/* Main program                */
/* SYPNOSIS: argv[0] host port */
/*-----------------------------*/
int main(int argc, char *argv[])
{

    /*---------------------------*/
    /*-- Licensing stuff       --*/
    /*---------------------------*/
    //Lic_t *CocoPop;
 
    /*-- MySQL stuff --*/
    mySqlCmd_t *mysqlCommand; 

    /*-- child pid --*/
    pid_t child_pid;
    char *ExCmdSTRING;
    char *CommunitySTRING;
    char *NodeIP;
    //char* CommunitySTRING = malloc(CNAMESIZE * sizeof(char));
    //char* NodeIP = (char *) malloc(sizeof(char) * 41);


    char *MySQLSverIP;
    char *APPLDIR = gnu_getcwd(); 
   
    char str1[15] = "ping"; /* Used in strcmp() define two strings str1, str2 and initialize str1 */ 
    char str2[15] = "";  

    /*-- start time --*/
    time_t startTime;

    /*-- master file descriptor list --*/
    fd_set master;

    /*-- temp file descriptor list for select() --*/
    fd_set read_fds;

    /*-- server address --*/
    struct sockaddr_in serveraddr;
    int saSize = sizeof(struct sockaddr);
 
    /*-- client address --*/
    struct sockaddr_in clientaddr;

    /*-- maximum file descriptor number --*/
    int fdmax;

    /*-- listening socket descriptor --*/
    int listener;

    /*-- newly accept()ed socket descriptor --*/
    int newfd;

    /*-- buffer for client data --*/
    char buf[MAXRPYBYTES];
    int nbytes, bytesRecv = 0;
    int totalbytes=0;
    CtrlCmdHeader_t *revcBuffer;
    char *clientCmdSTRING;
         
    RpyHeader_t  *rpyBuffer;
    size_t RPYHEADERLEN;

    size_t INTERMEDIATE_FSIZE = 0;  /* mem holder for intermediate output files */

    long RcvCmdLen = 0;
    int  RvcCnt = 0;

    RcvCmdLen = (long *) malloc(sizeof(long *));

    /*-- Remote control parameters --*/ 
    remoteCmd_t *REMCtrl;
    const char delim1[] = "'";
    const char delim2[] = " ";
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char *user = "clevermonitor";
    char *password = "cleverview7070";
    char *database = "CV4LINUXMASTER";
    int len;
    char ch;
    char *token, *cp, *remain;


    /*-- for pipe popen and pclose --*/
    int cres_fd;
    int defout;

    /*-- for setsockopt() SO_REUSEADDR, below --*/
    int yes = 1;
    int addrlen;
    int i;

    /*-- BEGIN --*/
    char *home, *host, *cv4home, *tmpSTRING, interSTRING;
    char *filename = (char *) malloc (sizeof(char) * 150);
    char *startuppath = (char *) malloc (sizeof(char) * 100);
    FILE *fp;


    home = getenv("HOME");
    host = getenv("HOSTNAME");
    fp=fopen("/etc/cv4env.conf", "rt");
    if (fp != NULL) {
       fscanf(fp, "%s", startuppath);
       fclose(fp);
       if (startuppath != NULL || (strcmp(startuppath, "") == 0)) {
          setenv("CV4_HOME", startuppath, 1);
          cv4home = getenv("CV4_HOME");
       }
    } else {
       setenv("CV4_HOME", "/opt/aes/cv4linux", 1);
    }
    cv4home = getenv("CV4_HOME");
    /* printf ("CV4_HOME=%s\n", cv4home); */

    startTime = time(NULL);
    printf("STARTING REAL-TIME MONITORING SERVICES... %s\n", (char *) ctime(&startTime));


    /*-- clear the master and temp sets --*/
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    
    RPYHEADERLEN = sizeof(long *) * 3 + sizeof(short *);

    /*-- get the listener --*/
    if((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Monitor-socket() error!");
        /*--just exit!--*/
        exit(1);
    }

    
    /*----------------------------------------------*/
    /* Redirect stderror and stdout to file         */
    /*----------------------------------------------*/
    //printf("%s Monitor socket() is OK...\n", (char *) ctime(&startTime));

    /*"address already in use" error message */
    if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        perror("Monitor socket-setsockopt() address in used!  You might want to run 'lsof | grep CLOSE_WAIT' and terminate any PIDs found.");
        exit(1);
    }

    //printf("Monitor socket-setsockopt() is OK...\n");


    /* bind */
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = htons(SERVER_PORT);
    memset(&(serveraddr.sin_zero), '\0', 8);

 
    if(bind(listener, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1)
    {
        perror("Monitor socket-bind() error!");
        exit(1);
    }
    //printf("Monitor socket-bind() is OK...\n");

    /*-- Check for valid license --*/
    MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
    //strcpy(MySQLSverIP, "148.100.33.39");
    strcpy(MySQLSverIP, getIPfromCnf());
    printf("Monitor socket-bind() on %s is OK...\n", MySQLSverIP);

    if (validatelicense(MySQLSverIP) == 1) { 
       return 1;  /*-- exit runtime --*/
       printf("This non-licensed program is now terminated.\n");
    }

    /* listen with backlog = 100 */
    /* backlog limits the number of outstanding connections in the socket's listen queue to 100 */
    if(listen(listener, 100) == -1)
    {
         perror("Monitor socket-listen() error!");
         exit(1);
    }

    //printf("Monitor socket-listen() is OK...\n");
    printf("CleverView(R) for TCP/IP on Linux is now listening on port 6688.\n");


    /* add the listener to the master set */
    FD_SET(listener, &master);

    /* keep track of the biggest file descriptor */
    fdmax = listener; /* so far, it's this one*/

    mysqlCommand = (mySqlCmd_t *) malloc(sizeof(mySqlCmd_t) * 1024);
    strcpy(mysqlCommand->monitorip, MySQLSverIP);

    /* re-name log file to old log file if exists */

    /*--------------------------------------------------------------*/
    /* loop forever, servicing connections via port SERVERPORT 6688 */
    /*--------------------------------------------------------------*/
    for(;;)
    {
        /* copy it */
       	read_fds = master;

        /* use select() to simulate asynchronous reads */
        if(select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1)
	{
	    perror("Monitor socket-select() error!");
    	    exit(1);
	}

	//printf("Monitor-select() is OK...\n");

	/*run through the existing connections looking for data to be read*/
    	for(i = 0; i <= fdmax; i++)
	{
	    if(FD_ISSET(i, &read_fds))
	    { 
                /* we got one... */
	        if(i == listener)
                {
	             /* handle new connections */
       		     addrlen = sizeof(clientaddr);

		     if((newfd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen)) == -1)
		     {
			    perror("Monitor socket-accept() error!");
		     } else {
			    /* printf("Monitor socket-accept() is OK...\n"); */

			    FD_SET(newfd, &master); /* add to master set */
			    if(newfd > fdmax)
			    { /* keep track of the maximum */
			         fdmax = newfd;
			    }
                            /* determine server inet address */
                            getsockname(newfd, (struct sockaddr *)&serveraddr, &saSize);
			    //printf("%s: server address %s on socket %d\n", argv[0], inet_ntoa(serveraddr.sin_addr), newfd);

                            startTime = time(NULL);
			    /* printf("%sNew connection from %s on socket %d\n", (char *) ctime(&startTime), inet_ntoa(clientaddr.sin_addr), newfd); */
		    }
		} else {
                    /* allocate memory for struct CtrlCmdHeader_t */
                    revcBuffer = (CtrlCmdHeader_t *) malloc(sizeof(CtrlCmdHeader_t) * CMDBUFFLEN);
                    /* initialize the buffer */
                    revcBuffer->CmdLength = 0;
                    revcBuffer->ProdCode = 0;
                    revcBuffer->CmdCode = 0;
                    revcBuffer->CmdDirective = 0;
                    memset(revcBuffer->CmdString, '\0', sizeof(char) * CMDBUFFLEN);

		    /* handle data from a client */
                    /* recvfrom(sockfd, buf, len, flags, NULL, NULL); */
		    if((nbytes = recv(i, revcBuffer, 512, 0)) <= 0)
		    {
			/* got error or connection closed by client */
			//if(nbytes == 0)
			// 	/* connection closed */
			//	printf("DEBUG:%s: socket %d hung up by client.\n", argv[0], i); 
			//else
			if(nbytes != 0)
				perror("recv() error!");

		    } else {
                        bytesRecv = 0;
                        nbytes=0;
                        RvcCnt = 0;

                        RcvCmdLen = ntohl(revcBuffer->CmdLength);
                        clientCmdSTRING = (char *) malloc(sizeof(char) * RcvCmdLen);
                        //printf("DEBUG-- RevcCmdLen: %d\n", RcvCmdLen);
                        strcpy(clientCmdSTRING, revcBuffer->CmdString);
                        //printf("DEBUG: Got out of while loop!  CmdLen=%d Actual command is %s\n", strlen(clientCmdSTRING), clientCmdSTRING);

			/* We got some data from a client!                       */
                        /* Parse the buffer according to CtrlCmdHeader structure */
                        /* and determine what needs to be done from the request. */
                        /* Perform the request and send output back to sender    */

                        /*-- Convert recieved buffer to host order byte --*/
                        revcBuffer->CmdLength = ntohl(revcBuffer->CmdLength);
                        revcBuffer->ProdCode = ntohl(revcBuffer->ProdCode);
                        revcBuffer->CmdCode = ntohl(revcBuffer->CmdCode);
                        revcBuffer->CmdDirective = ntohs(revcBuffer->CmdDirective);

                        printf("\tCmdLength: %d\n", revcBuffer->CmdLength);
                        printf("\tProductCode: %X\n", revcBuffer->ProdCode);
                        printf("\tCommandCode: %x\n", revcBuffer->CmdCode);
                        printf("\tCmdDirective: %d\n", revcBuffer->CmdDirective);
                        printf("\tCmdString: %s\n\n", clientCmdSTRING);

                        /* flush the stdout */
                        fflush(stdout);

                        char* ExCmdSTRING = malloc(CNAMESIZE * sizeof(char));
                        char* CommunitySTRING = malloc(CNAMESIZE * sizeof(char));
                        char* NodeIP = (char *) malloc(sizeof(char) * 41);

                        //ExCmdSTRING = (char *) malloc(sizeof(char) * 1024);
                        memset(ExCmdSTRING, '\0', sizeof(1024)); 
                        MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                        /* printf("DEBUG: MySQLIP=%s\n", MySQLSverIP); */

                        /*--------------------------------------------------*/ 
                        /* service requests that have correct ProdCode only */
                        /*--------------------------------------------------*/ 
                        if (revcBuffer->ProdCode == 0xABBABABE) {
			    /* Parse CommandCode */
                            switch(revcBuffer->CmdCode) {
			        case CMDCODE_CRITRES_MONITORING:
                                     /* Taking action base on command directive */
       			 	     switch(revcBuffer->CmdDirective) {
			 	         case CMD_START_DIRECTIVE:
			                     printf("starting critical resource monitoring wherever 'MonitorOnNow==1'\n");	
                                             /* 1.  et critres definitions from database */
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 /* do not wait for a looping script in the child_pid that never self-terminate */
                                                 //waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                 //printf("DEBUG-- child_pid finished\n"); 
                        
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = 24;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (rpyBuffer->RpyBufferLength == 0) { 
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to execute startnodemon script");
                                                 } else {
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Critical resources monitoring has started.");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");
                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                             } else if (child_pid == 0) {
                                                 //printf("Calling runMonitoringScript(1) \n");
                                                 runMonitoringScript(1);
                                                 _exit(EXIT_FAILURE);
                                             }
                                             else if (child_pid < 0)
                                                 printf("Failed to execute runMonitoringScript(1) script\n");

					     break;
				         case CMD_STOP_DIRECTIVE:
                                             printf("Stoping critical resources monitoring wherever 'MonitorOnNow==0'\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                 //printf("DEBUG-- child_pid finished\n"); 
                        
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = 24;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (rpyBuffer->RpyBufferLength == 0) { 
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to run stop scritical resource monitoring");
                                                 } else {
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Critical resources monitoring has stopped.");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                             } else if (child_pid == 0) {
                                                /* this is the child stopcresmon process. */
                                                if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r cres", NULL) == -1) {
                                                    fprintf(stderr,"execl Error!");
                                                    _exit(EXIT_FAILURE);
                                                }
                                             }
                                             else if (child_pid < 0)
                                                 printf("Failed to stop scritical resource monitoring\n");


				 	     break;
				         case CMD_STATUS_DIRECTIVE:
					     printf("Retrieve Critical Resources monitoring status:\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
 		                                 /* This is the parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                        
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/cresstatus.txt");
                                                 /*totalbytes =  getOutputFromFile("/tmp/cresstatus.txt",  buf);*/
                                                 totalbytes =  getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyEntries = 1;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) { 
                                                     strcpy(rpyBuffer->Output, "Critical resources monitoring status: NOT ACTIVE\n");
                                                 } else {
                                                     strcpy(rpyBuffer->Output, "Critical resources monitoring status: ACTIVE\n");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /*remove("/tmp/cresstatus.txt");*/
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                             
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                              } else if (child_pid == 0) {
                                                 /* This is the child ping process. */
                                                 strcpy(filename, "ps -elf | grep cv4CRES | grep -v grep | cut -c14-19 > ");
                                                 strcat(filename, cv4home);
                                                 strcat(filename, "/tmp/cresstatus.txt");
                                                 if (execl(SHELL, SHELL, "-c", filename, NULL) == -1) {
			                             fprintf(stderr,"execl Error!");
                                                     _exit(EXIT_FAILURE);
		                                 }
                                             }
                                             else if (child_pid < 0)
                                                 fprintf(stderr, "Failed to retrieve critical resource monitoring status.\n");

				         break;
                                     }
                                     break;
			        case CMDCODE_PORTMON_MONITORING:
                                     /* Taking action base on command directive */
    				     switch(revcBuffer->CmdDirective) {
				         case CMD_START_DIRECTIVE:
			                     printf("starting port monitoring wherever 'MonitorOnNow==1'\n");	
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 /* do not wait for a looping script in the child_pid that never self-terminate */
                                                 //waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                 //printf("DEBUG-- portmon child_pid finished\n"); 
                        
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = 24;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (rpyBuffer->RpyBufferLength == 0) { 
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to execute cv4PORT script");
                                                 } else {
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Port(s) monitoring started.");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                             } else if (child_pid == 0) {
                                                 //printf("Calling runMonitoringScript(2) \n");
                                                 runMonitoringScript(2);
                                                 _exit(EXIT_FAILURE);
                                             }
                                             else if (child_pid < 0)
                                                 printf("Failed to execute runMonitoringScript(2) script\n");

				 	     break;
				         case CMD_STOP_DIRECTIVE:
                                             printf("Stopping port monitoring wherever 'MonitorOnNow==0'\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                        
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = 24;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (rpyBuffer->RpyBufferLength == 0) { 
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to run stopportmon script");
                                                 } else {
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Port monitoring has stopped.");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                             } else if (child_pid == 0) {
                                                /* this is the child stopportmon process. */
                                                if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r port", NULL) == -1) {
                                                    fprintf(stderr,"execl Error!");
                                                    _exit(EXIT_FAILURE);
                                                }
                                             }
                                             else if (child_pid < 0)
                                                 printf("Failed to execute stopportmon script\n");

				             break;
				         case CMD_STATUS_DIRECTIVE:
					     printf("Retrieve PortMon monitoring status:\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
 		                                 /* This is the parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                        
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/portmonstatus.txt");
                                                 /*totalbytes =  getOutputFromFile("/tmp/portmonstatus.txt",  buf);*/
                                                 totalbytes =  getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyEntries = 1;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) { 
                                                     strcpy(rpyBuffer->Output, "PortMon monitoring status: NOT ACTIVE\n");
                                                 } else {
                                                     strcpy(rpyBuffer->Output, "PortMon monitoring status: ACTIVE\n");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /*remove("/tmp/portmonstatus.txt");*/
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                             
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                              } else if (child_pid == 0) {
                                                 /* This is the child ping process. */
                                                 strcpy(filename, "ps -elf | grep cv4PORT | grep -v grep | cut -c14-19 > ");
                                                 strcat(filename, cv4home);
                                                 strcat(filename, "/tmp/portmonstatus.txt");
                                                 if (execl(SHELL, SHELL, "-c", filename, NULL) == -1) {
			                             fprintf(stderr,"execl Error!");
                                                     _exit(EXIT_FAILURE);
		                                 }
                                             }
                                             else if (child_pid < 0)
                                                 fprintf(stderr, "Failed to retrieve PortMon monitoring status.\n");
				         break;
                                     }
				     break;
			        case CMDCODE_MIB_MONITORING:
                                     /* Taking action base on command directive */
				     switch(revcBuffer->CmdDirective) {
				         case CMD_START_DIRECTIVE:
			                     //printf("Start node monitoring wherever 'MonitorOnNow==1'\n");	
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 /* do not wait for a looping script in the child_pid that never self-terminate */
                                                 //waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                 //printf("DEBUG-- child_pid finished\n"); 
                        
                                                 /* send output back to client by accessing the file /var/log/cv4log/startnodemonout.txt */
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = 24;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (rpyBuffer->RpyBufferLength == 0) { 
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to execute startnodemon script");
                                                 } else {
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Node(s) monitoring started\n");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");
                      
                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                             } else if (child_pid == 0) {
                                                 /* this is the child RUNALL.sh process. */
                                                 //printf("Calling runMonitoringScript(3) \n");
                                                 /* Stop front-end from calling repeatedtedly on every node
                                                 runMonitoringScript(3); */
                                                 _exit(EXIT_FAILURE);
                                             }
                                             else if (child_pid < 0)
                                                 printf("Failed to execute node monitoring script\n");

					     break;

				         case CMD_STOP_DIRECTIVE:
                                             printf("Stop node monitoring wherever 'MonitorOnNow==0'\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                 //printf("DEBUG-- child_pid finished\n"); 
                        
                                                 /* send output back to client by accessing the file /var/log/cv4log/stopnodemon.txt */
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = 24;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (rpyBuffer->RpyBufferLength == 0) { 
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to run stopnodemon script");
                                                 } else {
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Node monitoring has been stopped.");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                             } else if (child_pid == 0) {
                                                /* this is the child stopnodemon process. */
                                                if (execl(SHELL, SHELL, "-c", "cv4monwrapper -r node", NULL) == -1) {
                                                    fprintf(stderr,"execl Error!");
                                                    _exit(EXIT_FAILURE);
                                                }
                                             }
                                             else if (child_pid < 0)
                                                 printf("Failed to execute stopnodemon script\n");
					     break;

				         case CMD_STATUS_DIRECTIVE:
					     printf("Retrieve Node monitoring status:\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
 		                                 /* This is the parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                        
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/nodemonstatus.txt");
                                                 /*totalbytes =  getOutputFromFile("/tmp/nodemonstatus.txt",  buf);*/
                                                 totalbytes =  getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyEntries = 1;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) { 
                                                     strcpy(rpyBuffer->Output, "Node monitoring status: NOT ACTIVE\n");
                                                 } else {
                                                     strcpy(rpyBuffer->Output, "Node monitoring status: ACTIVE\n");
                                                 } 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /*remove("/tmp/nodenonstatus.txt");*/
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                             
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    

                                              } else if (child_pid == 0) {
                                                 /* This is the child process. */
                                                 strcpy(filename, "ps -elf | grep cv4TCPIPv4 | grep -v grep | cut -c14-19 > ");
                                                 strcat(filename, cv4home);
                                                 strcat(filename, "/tmp/nodemonstatus.txt");
                                                 if (execl(SHELL, SHELL, "-c", filename, NULL) == -1) {
			                             fprintf(stderr,"execl Error!");
                                                     _exit(EXIT_FAILURE);
		                                 }
                                             }
                                             else if (child_pid < 0)
                                                 fprintf(stderr, "Failed to retrieve Node monitoring status.\n");
				         break;
                                     }
				     break;
			        case CMDCODE_NOTIFICATION:
                                     /* TODO: implement enabling notification */
				     break;

                                /* begin real-time commands */
			        case CMDCODE_REALTIME_SYSUTIL:
			  	     switch(revcBuffer->CmdDirective) {
				         case CMD_PING_DIRECTIVE:
                                             /* Sanity check pass-in parameters */
                                             memset(str1, '\0', 14);
                                             memset(str2, '\0', 14);
                                             strncpy(str1, "ping", 4);  /* copy "ping" into str1 */
                                             strncpy(str2, clientCmdSTRING, 4);  /* copy first 4 characters of CmdString to str2 */
                                             /* test if str1 is identical to str2 */
                                             if (strncmp(str2, str1, 4) != 0) {
                                                 //printf("DEBUG-- pass-in command %s is not a valid command.\n", str2);
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 rpyBuffer->RpyBufferLength = 68;
                                                 rpyBuffer->ReturnCode = 1;
                                                 rpyBuffer->ReasonCode = 1;
                                                 rpyBuffer->RpyEntries = 5;
                                                 strcpy(rpyBuffer->Output, "WARNING: Failed to execute ping command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                 strcat(rpyBuffer->Output, "\nUsage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]\n");
                                                 strcat(rpyBuffer->Output, "            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]\n");
                                                 strcat(rpyBuffer->Output, "            [-M mtu discovery hint] [-S sndbuf]\n");
                                                 strcat(rpyBuffer->Output, "            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination\n");

                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else {
                                                 /* Valid ping command.  Let's boogie */
					         printf("ping output:\n");
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
 		                                     /* This is the parent process */
                                                     waitpid(child_pid, 0, 0);      /* wait until child process finished */

                                                     //printf("DEBUG-- Child exited with a %d value\n",child_pid);
                        
                                                     /* send output back to client by accessing the file /var/log/cv4log/pingout.txt */
                                                     /* allocate memory for struct RpyRealtime_t */
                                                     rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                     memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/pingout.txt");
                                                     //printf("DEBUG--PING cmd cv4home: %s filename:%s\n", cv4home, filename);
                                                     fprintf(stdout, "PING cmd cv4home: %s filename:%s\n", cv4home, filename);
                                                     /*totalbytes =  getOutputFromFile("/tmp/pingout.txt",  buf);*/
                                                     totalbytes = getOutputFromFile(filename,  buf);
                                                     //printf("DEBUG--PING cmd filename: %s Totalbytes:%d\n", filename, totalbytes);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) { 
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 5;
                                                         strcpy(rpyBuffer->Output, "Failed to execute ping command:  ");
                                                         strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                         
                                                         strcat(rpyBuffer->Output, "\nUsage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]\n");
                                                         strcat(rpyBuffer->Output, "            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]\n");
                                                         strcat(rpyBuffer->Output, "            [-M mtu discovery hint] [-S sndbuf]\n");
                                                         strcat(rpyBuffer->Output, "            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination\n");

                                                     } else {
                                                         /*FILE *fp=fopen("/tmp/pingout.txt", "rb");*/
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                     } 
                                                     rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                     //remove("/tmp/pingout.txt");
                                                     remove(filename);
                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                     /* send output back to sender */
			                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                                 perror("send() error!");

                                                     //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                     free(rpyBuffer);  /* deallocate memory */                    

                                                  } else if (child_pid == 0) {
                                                     /* This is the child ping process. */
                                                     strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                     strcat(clientCmdSTRING, cv4home);
                                                     strcat(clientCmdSTRING, "/tmp/pingout.txt; sleep 1");
                                                     if (execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL) == -1) {
			                                 fprintf(stderr,"execl Error!");
                                                         _exit(EXIT_FAILURE);
		                                     }
                                                 }
                                                 else if (child_pid < 0)
                                                     fprintf(stderr, "Failed to execl ping command\n");
                                             }

					     break;
				         case CMD_PING6_DIRECTIVE:
                                             /* Sanity check pass-in parameters */
                                             memset(str1, '\0', 14);
                                             memset(str2, '\0', 14);
                                             strncpy(str1, "ping6", 5);  /* copy "ping6" into str1 */
                                             strncpy(str2, clientCmdSTRING, 5);  /* copy first 5 characters of CmdString to str2 */
                                             /* test if str1 is identical to str2 */
                                             if (strncmp(str2, str1, 5) != 0) {
                                                 //printf("DEBUG-- pass-in command %s is not a valid command.\n", str2);
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 rpyBuffer->RpyBufferLength = 68;
                                                 rpyBuffer->ReturnCode = 1;
                                                 rpyBuffer->ReasonCode = 1;
                                                 rpyBuffer->RpyEntries = 5;
                                                 strcpy(rpyBuffer->Output, "WARNING: Failed to execute ping6 command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                 strcat(rpyBuffer->Output, "\nUsage: ping6 [-LUdfnqrvVaA] [-c count] [-i interval] [-w deadline]\n");
                                                 strcat(rpyBuffer->Output, "             [-p pattern] [-s packetsize] [-t ttl] [-I interface]\n");
                                                 strcat(rpyBuffer->Output, "             [-M mtu discovery hint] [-S sndbuf]\n");
                                                 strcat(rpyBuffer->Output, "             [-F flow label] [-Q traffic class] [hop1 ...] destination \n"); 
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else {
                                                 /* Valid ping command.  Let's boogie */
					         //printf("ping output:\n");
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
 		                                     /* This is the parent process */
                                                     waitpid(child_pid, 0, 0);      /* wait until child process finished */

                                                     //printf("DEBUG-- Child exited with a %d value\n",child_pid);
                        
                                                     /* send output back to client by accessing the file /var/log/cv4log/pingout.txt */
                                                     /* allocate memory for struct RpyRealtime_t */
                                                     rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                     memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/pingout.txt");
                                                     //printf("DEBUG--PING cmd cv4home: %s filename:%s\n", cv4home, filename);
                                                     //fprintf(stdout, "PING cmd cv4home: %s filename:%s\n", cv4home, filename);
                                                     /*totalbytes =  getOutputFromFile("/tmp/pingout.txt",  buf);*/
                                                     totalbytes = getOutputFromFile(filename,  buf);
                                                     //printf("DEBUG--PING cmd filename: %s Totalbytes:%d\n", filename, totalbytes);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) { 
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 5;
                                                         strcpy(rpyBuffer->Output, "Failed to execute ping6 command:  ");
                                                         strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                         strcat(rpyBuffer->Output, "\nUsage: ping6 [-LUdfnqrvVaA] [-c count] [-i interval] [-w deadline]\n");
                                                         strcat(rpyBuffer->Output, "             [-p pattern] [-s packetsize] [-t ttl] [-I interface]\n");
                                                         strcat(rpyBuffer->Output, "             [-M mtu discovery hint] [-S sndbuf]\n");
                                                         strcat(rpyBuffer->Output, "             [-F flow label] [-Q traffic class] [hop1 ...] destination \n"); 

                                                     } else {
                                                         /*FILE *fp=fopen("/tmp/pingout.txt", "rb");*/
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                     } 
                                                     rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                     //remove("/tmp/pingout.txt");
                                                     remove(filename);
                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                     /* send output back to sender */
			                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                                 perror("send() error!");

                                                     //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                     free(rpyBuffer);  /* deallocate memory */                    

                                                  } else if (child_pid == 0) {
                                                     /* This is the child ping process. */
                                                     strcat(clientCmdSTRING, " 2>&1| tee ");
                                                     strcat(clientCmdSTRING, cv4home);
                                                     strcat(clientCmdSTRING, "/tmp/pingout.txt; sleep 1");
                                                     if (execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL) == -1) {
			                                 fprintf(stderr,"execl Error!");
                                                         _exit(EXIT_FAILURE);
		                                     }
                                                 }
                                                 else if (child_pid < 0)
                                                     fprintf(stderr, "Failed to execute ping6 command\n");
                                             }

					     break;
				        case CMD_TRACERT_DIRECTIVE:
                                             /* Sanity check pass-in parameters */
                                             memset(str1, '\0', 14);
                                             memset(str2, '\0', 14);
                                             strncpy(str1, "traceroute", 10);  /* copy "traceroute" into str1 */
                                             strncpy(str2, clientCmdSTRING, 10);  /* copy first 10 characters of CmdString to str2 */
                                             /* test if str1 is identical to str2 */
                                             if (strncmp(str2, str1, 10) != 0) {
                                                 //printf("DEBUG-- pass-in command %s is not a valid command.  Expected 'traceroute'\n", str2);
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 rpyBuffer->RpyBufferLength = 68;
                                                 rpyBuffer->ReturnCode = 1;
                                                 rpyBuffer->ReasonCode = 1;
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute traceroute command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                 strcat(rpyBuffer->Output, "\nUsage:\n");
                                                 strcat(rpyBuffer->Output, "    traceroute [ -46dFITUnrAV ] [ -f first_ttl ] [ -g gate,... ] [ -i device ] [ -m max_ttl ] [ -N squeries ] [ -p port ] [ -t tos ] [ -l flow_label ] [ -w waittime ] [ -q nqueries ] [ -s src_addr ] [ -z sendwait ] host [ packetlen ]\n");
                                                 strcat(rpyBuffer->Output, "\nNote, on some system where traceroute is not exported to user, you must use absolute path '/usr/sbin/traceroute' instead.\n");
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else {
                                                 /* Valid traceroute command.  Let's bugie */
					         //printf("traceroute output:\n");
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
                                                     /* parent process */
                                                     waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                     //printf("DEBUG-- child_pid %d finished\n", child_pid); 
                        
                                                     /* send output back to client by accessing the file /var/log/cv4log/tracertout.txt */
                                                     /* allocate memory for struct RpyRealtime_t */
                                                     rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                     memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                     strcpy(rpyBuffer->Output, "");
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/tracertout.txt");
                                                     /*totalbytes =  getOutputFromFile("/tmp/tracertout.txt",  buf);*/
                                                     totalbytes =  getOutputFromFile(filename,  buf);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->RpyBufferLength = totalbytes;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) { 
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 3;
                                                         strcpy(rpyBuffer->Output, "Failed to execute traceroute command:  ");
                                                         strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                         strcat(rpyBuffer->Output, "\nUsage:\n");
                                                         strcat(rpyBuffer->Output, "    traceroute [ -46dFITUnrAV ] [ -f first_ttl ] [ -g gate,... ] [ -i device ] [ -m max_ttl ] [ -N squeries ] [ -p port ] [ -t tos ] [ -l flow_label ] [ -w waittime ] [ -q nqueries ] [ -s src_addr ] [ -z sendwait ] host [ packetlen ]\n");
                                                         strcat(rpyBuffer->Output, "\nNote, on some system where traceroute is not exported to user, you must use absolute path '/usr/sbin/traceroute' instead.\n");
                                                         rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                     } else {
                                                         /*FILE *fp=fopen("/tmp/tracertout.txt", "rb");*/
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                         rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                     } 
                                                     remove(filename);
                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                     /* send output back to sender */
			                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                                 perror("send() error!");
                      
                                                     //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                     free(rpyBuffer);  /* deallocate memory */                    

                                                 } else if (child_pid == 0) {
                                                    /* this is the child traceroute process. */
                                                     strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                     strcat(clientCmdSTRING, cv4home);
                                                     strcat(clientCmdSTRING, "/tmp/tracertout.txt; sleep 1");
                                                     execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                     _exit(EXIT_FAILURE);
                                                 }
                                                 else if (child_pid < 0)
                                                     printf("Failed to execute traceroute command\n");
                                             }
					     break;
				        case CMD_TRACERT6_DIRECTIVE:
                                             /* Sanity check pass-in parameters */
                                             /*
                                                e.g. traceroute6 -m 30 -q 6 -i eth0 fe80::212:3fff:fef0:ae2e
                                                     traceroute -6 -m 30 -i eth0 2001:470:0:170::b869:d260
                                              */
                                             memset(str1, '\0', 14);
                                             memset(str2, '\0', 14);
                                             strncpy(str1, "traceroute6", 11);  /* copy "traceroute" into str1 */
                                             strncpy(str2, clientCmdSTRING, 11);  /* copy first 11 characters of CmdString to str2 */
                                             /* test if str1 is identical to str2 */
                                             if (strncmp(str2, str1, 11) != 0) {
                                                 //printf("DEBUG-- pass-in command %s is not a valid command.  Expected 'traceroute6'\n", str2);
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 rpyBuffer->RpyBufferLength = 69;
                                                 rpyBuffer->ReturnCode = 1;
                                                 rpyBuffer->ReasonCode = 1;
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute traceroute6 command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                 strcat(rpyBuffer->Output, "\nUsage:\n");
                                                 strcat(rpyBuffer->Output, "    traceroute6 [-nFV] [-f first_ttl] [-m max_hops] [-p port] [-S source_addr] [-I interface] [-g gateway] [-t tos] [-w timeout] [-q nqueries] host [packetlen] \n");
                                                 strcat(rpyBuffer->Output, "\nNote, on some system where traceroute6 is not exported to user, you must use absolute path '/usr/sbin/traceroute6' instead.\n");
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else {
                                                 /* Valid traceroute command.  Let's bugie */
					         //printf("traceroute output:\n");
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
                                                     /* parent process */
                                                     waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                     //printf("DEBUG-- child_pid %d finished\n", child_pid); 
                        
                                                     /* send output back to client by accessing the file /var/log/cv4log/tracertout.txt */
                                                     /* allocate memory for struct RpyRealtime_t */
                                                     rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                     memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                     strcpy(rpyBuffer->Output, "");
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/tracertout.txt");
                                                     /*totalbytes =  getOutputFromFile("/tmp/tracertout.txt",  buf);*/
                                                     totalbytes =  getOutputFromFile(filename,  buf);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->RpyBufferLength = totalbytes;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) { 
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 3;
                                                         strcpy(rpyBuffer->Output, "Failed to execute traceroute6 command:  ");
                                                         strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                         strcat(rpyBuffer->Output, "\nUsage:\n");
                                                         strcat(rpyBuffer->Output, "    traceroute6 [-nFV] [-f first_ttl] [-m max_hops] [-p port] [-S source_addr] [-I interface] [-g gateway] [-t tos] [-w timeout] [-q nqueries] host [packetlen] \n");
                                                         strcat(rpyBuffer->Output, "\nNote, on some system where traceroute is not exported to user, you must use absolute path '/usr/sbin/traceroute' instead.\n");
                                                         rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                     } else {
                                                         /*FILE *fp=fopen("/tmp/tracertout.txt", "rb");*/
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                         rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                     } 
                                                     remove(filename);
                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                     /* send output back to sender */
			                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                                 perror("send() error!");
                      
                                                     //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                     free(rpyBuffer);  /* deallocate memory */                    

                                                 } else if (child_pid == 0) {
                                                    /* this is the child traceroute process. */
                                                     strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                     strcat(clientCmdSTRING, cv4home);
                                                     strcat(clientCmdSTRING, "/tmp/tracertout.txt; sleep 1");
                                                     execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                     _exit(EXIT_FAILURE);
                                                 }
                                                 else if (child_pid < 0)
                                                     printf("Failed to execute traceroute6 command\n");
                                             }
					     break;

                                          
                                        
                                        case CMD_DOCKERVIEW_DIRECTIVE: 
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_DIRECTIVE: 
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_CPU_INFO: /*-- "top -b -n1 -i | head -n5 | grep 'Cpu' 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_CPU_INFO, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_DEVICE_DRIVER:  //*-- "cat /proc/driver/* 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_DEVICE_DRIVER, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_FILE_LOCKS:  //*-- "cat /proc/locks 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_FILE_LOCKS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_FILE_SYSTEM:  //*-- "cat /proc/filesystems 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_FILE_SYSTEM, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_IO_PORTS:  //*-- "cat /proc/ioports 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_IO_PORTS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_IO_STATS:  /*system IO Stats*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_IO_STATS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_ARP_TABLE:  /*-- "cat /proc/buddyinfo 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_ARP_TABLE, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_MODULES:  /*-- "cat /proc/modules 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_MODULES, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_MEM_INFO: //*-- "top -b -n1 -i | head -n5 | grep 'Mem :' 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_MEM_INFO, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_CONNECTIONS: //*-- "cat /proc/net/dev 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_CONNECTIONS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_INTERFACES: //*-- "cat /proc/net/protocols 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_INTERFACES, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_TCPIPV4: /**need to doublecheck**/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_TCPIPV4, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_TCPIPV6: //*-- "cat /proc/uptime /proc/version 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_TCPIPV6, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_SOCKET_IPV4: //*-- "cat /proc/modules 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_SOCKET_IPV4, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_SOCKET_IPV6: //*-- "cat /proc/modules 2>&1 > " --*/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_SOCKET_IPV6, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_SUMMARY:
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_SUMMARY, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_UDP_IPv4:
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_UDP_IPv4, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_NET_UDP_IPV6:
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_NET_UDP_IPV6, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_OPEN_FILES:
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_OPEN_FILES, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_PROCESS_STATS:
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_PROCESS_STATS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_SYSTEM_STATS:
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_SYSTEM_STATS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
                                        case CMD_SYSVIEW_PARTITIONS:
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             //run_sysstat(CMD_SYSVIEW_PARTITIONS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             run_sysview( i, clientCmdSTRING, MySQLSverIP, cv4home);

                                             break;
 
 
                                        /*-- Starting DOCKER real-time commands --*/ 
                                        case CMD_DOCKER_CONTAINER_ACTIVE_STATS:  /* 0x28 */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINER_ACTIVE_STATS) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_ACTIVE_STATS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;

                                        case CMD_DOCKER_CONTAINER_ALL_STATS: /* 0x29 */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINER_ALL_STATS) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_ALL_STATS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_CONTAINTER_ACTIVE_SUMMARY:  /* 0x2A */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINTER_ACTIVE_SUMMARY) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINTER_ACTIVE_SUMMARY, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_CONTAINTER_ALL_SUMMARY:  /* 0x2B */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINTER_ALL_SUMMARY) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINTER_ALL_SUMMARY, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_IMAGE_LIST:  /* 0x2C */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_IMAGE_LIST) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_IMAGE_LIST, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_HOSTING_INFO:  /* 0x2D */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_HOSTING_INFO) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_HOSTING_INFO, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_CONTAINER_DIFF:  /* 0x2E */
                                             /* clientCmdSTRING contain 2 tokens {nodeIP and container_id} */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINER_DIFF) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_DIFF, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_CONTAINER_INSPECT:  /* 0x2F */
                                             /* clientCmdSTRING contain 2 tokens {nodeIP and container_id} */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINER_INSPECT) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_INSPECT, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_CONTAINER_LOGS:  /* 0x2F */
                                             /* clientCmdSTRING contain 2 tokens {nodeIP and container_id} */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINER_LOGS) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_LOGS, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_CONTAINER_TOP:  /* 0x2F */
                                             /* clientCmdSTRING contain 2 tokens {nodeIP and container_id} */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_CONTAINER_TOP) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_TOP, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_IMAGE_HISTORY:  /* 0x2F */
                                             /* clientCmdSTRING contain 2 tokens {nodeIP and image_id} */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_IMAGE_HISTORY) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_IMAGE_HISTORY, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
 
                                        case CMD_DOCKER_CONTAINER_CPUUSAGE:  /* 0x2F */
                                             /* clientCmdSTRING contain 2 tokens {nodeIP and image_id} */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_IMAGE_HISTORY) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_CPUUSAGE, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
                                        case CMD_DOCKER_CONTAINER_MEMUSAGE:  /* 0x2F */
                                             /* clientCmdSTRING contain 2 tokens {nodeIP and image_id} */
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
//printf("BEFORErun_dockerstat--(CMD_DOCKER_IMAGE_HISTORY) clientCmdSTRING:%s\n", clientCmdSTRING);
                                             run_dockerstat(CMD_DOCKER_CONTAINER_MEMUSAGE, i, clientCmdSTRING, MySQLSverIP, cv4home);
                                             break;
 
 
 
 
 
 

                                        case CMD_REMOTECTRL_DIRECTIVE:
                                             /* allocate memory for struct RpyRealtime_t */
                                             rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                             memset(rpyBuffer->Output, '\0', sizeof(2048));
                                             rpyBuffer->ReturnCode = 1;
                                             rpyBuffer->ReasonCode = 1;
                                             rpyBuffer->ProdCode = PRODUCTCODE;
                                             


                                             /*****
                                              *-- 1. parse the clientCmdSTRING to get action_label 
                                              *****/
                                             fprintf(stdout, "\nDEBUG CMD_REMOTECTRL_DIRECTIVE:%s\n", clientCmdSTRING);
                                             REMCtrl = (remoteCmd_t *) malloc(sizeof(RpyHeader_t) * 1024);
                                             cp = strdupa (clientCmdSTRING);                       /* Make writable copy.  */
                                             strcpy(REMCtrl->actionlabel, strtok (cp, delim1));    /* token => action label */

                                             token = strtok (NULL, delim1);                        /* remining string */
                                             remain = strdupa (token);
                                             strcpy(REMCtrl->targetip, strtok (remain, delim2));   /* remote ip address */
                                             strcpy(REMCtrl->targetuserid, strtok (NULL, delim2)); /* remote userid */
                                             strcpy(REMCtrl->targetpasswd, strtok (NULL, delim2)); /* remote password */
                                             do {
                                                 token = strtok (NULL, delim2);
                                                 if (token != NULL) {
                                                     strcat(REMCtrl->args, token);        /* trailing arguments */
                                                     strcat(REMCtrl->args, " ");
                                                 }
                                             } while (token != NULL);
                                             /*****
                                              *-- 2. retrieve mysql table for action_label 
                                              *****/
                                             MySQLSverIP=inet_ntoa(serveraddr.sin_addr);
                                             conn = mysql_init(NULL);

                                             /* Connect to database */
                                             if (!mysql_real_connect(conn, MySQLSverIP, user, password, database, 0, NULL, 0))
                                             {
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Could not connect to application database");
                                             }

                                             /* send SQL query */
                                             if (mysql_query(conn, "SELECT ActionLabel, ActionType, ActionLabelContent, bSudo FROM remote_controls_conf")) 
                                             {
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Application database corrupted");
                                             }
					     //else 
					     //{
                                             //    printf("DEBUG: Connected to database %s on %s\n", database, MySQLSverIP);
					     //}

                                             res = mysql_use_result(conn);

                                             /* output table name */
                                             REMCtrl->isFound = 0;
                                             while ((row = mysql_fetch_row(res)) != NULL)
                                             {
                                                 if (strcmp(row[0], REMCtrl->actionlabel) == 0) 
                                                 {
                                                     /* found the matching action label in database */
                                                     REMCtrl->isFound = 1;
                                                     strcpy(REMCtrl->actiontype, row[1]);
                                                     strcpy(REMCtrl->actionsource, row[2]);
                                                     strcpy(REMCtrl->isSudo, row[3]);
                                                 }
                                             } 
                                             /* close connection */
                                             mysql_free_result(res);
                                             mysql_close(conn);

                                             /*****
                                              * sanity checking
                                              *****/
                                             if ( strlen(REMCtrl->actionlabel) == 0) { 
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Invalid action label");
                                             }
                                             else if ( strlen(REMCtrl->actiontype) == 0) {
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Invalid action type");
                                             }
                                             else if ( strlen(REMCtrl->targetip) == 0) {
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Invalid remote ip address");
                                             }
                                             else if ( strlen(REMCtrl->targetuserid) == 0) { 
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Invalid remote target userid");
                                             }
                                             else if ( strlen(REMCtrl->targetpasswd) == 0) {
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Invalid remote target password");
                                             }
                                             else if ( strlen(REMCtrl->actionsource) == 0) {
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Action label contains no source");
                                             }
                                             else if ( REMCtrl->isFound == 0 ) {
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                 strcat(rpyBuffer->Output, clientCmdSTRING);
                                                 strcpy(rpyBuffer->Output, "Reason: Action not registered in the databased");
                                             }

                                             /*****
                                             * 3. Perform remote control action
                                             *     3.1 if action_type=SYSTEMCMD then    
                                             *         format cmdstring and send to remmote via plink 
                                             *     3.2 if action_type=USERDEFINED then  
                                             *         copy script to remote using pscp 
                                             *         format cmdString and send to remote via plink
                                             *****/
                                             if ( REMCtrl->isFound == 1 ) {
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
                                                     /*-- in parent process --*/
                                                     waitpid(child_pid, 0, 0);        /* wait until child process finished */

                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/remotecontrol.txt");
                                                     totalbytes =  getOutputFromFile(filename,  buf);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->RpyBufferLength = totalbytes;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) {
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 2;
                                                         strcpy(rpyBuffer->Output, "Failed to execute remote action command:  ");
                                                         strcat(rpyBuffer->Output, clientCmdSTRING);
                                                         strcat(rpyBuffer->Output, "\nUsage: 'action_label' remote_target_userid remote_target_password remote_target_ip [additional params]\n");
                                                         rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;

                                                         /* Write error onto mobile_log table */
                                                         memset(ExCmdSTRING, '\0', sizeof(1024));
                                                         strcpy(ExCmdSTRING, "INSERT INTO mobile_log(MonitorIP, UserID, ActionLabelSelected,");
                                                         strcat(ExCmdSTRING, "LastTargetNodeIP, ActionLabelLastRunDate, ActionLabelLastRunTime,");
                                                         strcat(ExCmdSTRING, " ActionLabelStatus) VALUES('");
                                                         strcat(ExCmdSTRING, MySQLSverIP);
                                                         strcat(ExCmdSTRING, "', '");
                                                         strcat(ExCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(ExCmdSTRING, "', '");
                                                         strcat(ExCmdSTRING, REMCtrl->actionlabel);
                                                         strcat(ExCmdSTRING, "', '");
                                                         strcat(ExCmdSTRING, REMCtrl->targetip);
                                                         strcat(ExCmdSTRING, "', CURRENT_DATE(), CURRENT_TIME(), 'ERR') ON DUPLICATE KEY UPDATE ActionLabelLastRunDate = CURRENT_DATE(), ActionLabelLastRunTime = CURRENT_TIME(), ActionLabelStatus='ERR';");
                                                         //printf("--DEBUG-- UPDATE to mobile_log:\n%s\n", ExCmdSTRING);
                                                         strcpy(mysqlCommand->sqlcmdstmt, ExCmdSTRING);
                                                         mySQLexec(mysqlCommand);   /*-- send sqlstmt to database --*/
                                                     } else {
                                                         strcpy(filename, cv4home);
                                                         strcat(filename, "/tmp/remotecontrol.txt");
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 3072);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                         rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                     }
                                                     remove(filename);

                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                     /* send output back to sender */
                                                     if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                         perror("send() error!");

                                                     //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     //printf("Contents:\n%s\n", rpyBuffer->Output);

                                                     /* Update mobile_log */
                                                     /* INSERT INTO mobile_log(MonitorName, MonitorIP, UserID, ActionLabelSelected, 
                                                                      LastTargetNodeIP, ActionLabelLastRunDate, ActionLabelLastRunTime, 
                                                                      ActionLabelStatus) VALUES() 
                                                                      ON DUPLICATE KEY UPDATE set ActionLabelLastRunDate='', 
                                                                      ActionLabelLastRunTime='', ActionLabelStatus=''; 
                                                      */

                                                     //CmdSTRING = (char *) malloc(sizeof(char) * 1024);
                                                     memset(ExCmdSTRING, '\0', sizeof(1024));
                                                     strcpy(ExCmdSTRING, "INSERT INTO mobile_log(MonitorIP, UserID, ActionLabelSelected,");
                                                     strcat(ExCmdSTRING, "LastTargetNodeIP, ActionLabelLastRunDate, ActionLabelLastRunTime,");
                                                     strcat(ExCmdSTRING, " ActionLabelStatus) VALUES('");
                                                     strcat(ExCmdSTRING, MySQLSverIP);
                                                     strcat(ExCmdSTRING, "', '");
                                                     strcat(ExCmdSTRING, REMCtrl->targetuserid);
                                                     strcat(ExCmdSTRING, "', '");
                                                     strcat(ExCmdSTRING, REMCtrl->actionlabel);
                                                     strcat(ExCmdSTRING, "', '");
                                                     strcat(ExCmdSTRING, REMCtrl->targetip);
                                                     strcat(ExCmdSTRING, "', CURRENT_DATE(), CURRENT_TIME(), 'OK");
//                                                     strcat(ExCmdSTRING, "', CURRENT_DATE(), CURRENT_TIME(), 'OK', '");

//                                                     tmpSTRING = (char *) malloc(rpyBuffer->RpyBufferLength);
//                                                     interSTRING = (char *) malloc(rpyBuffer->RpyBufferLength);
//                                                     strcpy(tmpSTRING, trim(rpyBuffer->Output));
//                                                     printf("Out=%s\n", tmpSTRING);
//                                                     strcpy(interSTRING, str_replace(tmpSTRING, "'", " "));
//                                                     printf("Out=%s\n", interSTRING);
//                                                     strcpy(tmpSTRING, str_replace(interSTRING, "`", " "));
//                                                     printf("Out=%s\n", tmpSTRING);
//
//                                                     strcat(CmdSTRING, tmpSTRING);
                                                     strcat(ExCmdSTRING, "') ON DUPLICATE KEY UPDATE ActionLabelLastRunDate = CURRENT_DATE(), ActionLabelLastRunTime = CURRENT_TIME();");
                                                     //printf("--DEBUG-- UPDATE to mobile_log:\n%s\n", CmdSTRING);
                                                     strcpy(mysqlCommand->sqlcmdstmt, ExCmdSTRING);
                                                     mySQLexec(mysqlCommand);   /*-- send sqlstmt to database --*/
                                                      
                                                     free(rpyBuffer);  /* deallocate memory */

                                                 } else if (child_pid == 0) {
                                                     /*-- this is the child process. --*/

                                                     if (strcmp(REMCtrl->actiontype, "SYSTEMCMD") == 0)
                                                     {
                                                         /* 3.1 send plink with direct from REMCtrl->actionsource */
                                                         /* plink -2 -l userid -pw password host -m myscript.sh */
                                                         //strcpy(clientCmdSTRING, "echo '");
                                                         //strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                         //strcat(clientCmdSTRING, "' | ");
                                                         //strcat(clientCmdSTRING, "plink -2 -l ");

                                                         if ( strcmp(REMCtrl->isSudo, "1") == 0 ) {
                                                             strcpy(clientCmdSTRING, "echo '");
                                                             strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                             strcat(clientCmdSTRING, "' | sudo -S plink -2 -l ");
                                                         } else
                                                             strcpy(clientCmdSTRING, "plink -2 -l ");
                                                    
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, " -pw ");
                                                         strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                         strcat(clientCmdSTRING, " ");
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, "@");
                                                         strcat(clientCmdSTRING, REMCtrl->targetip);
                                                         strcat(clientCmdSTRING, " ");
                                                         strcat(clientCmdSTRING, REMCtrl->actionsource);
                                                         strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                         strcat(clientCmdSTRING, cv4home);
                                                         strcat(clientCmdSTRING, "/tmp/remotecontrol.txt");

                                                         //printf("--DEBUG-- (SYSTEMCMD)clientCmdSTRING:\n%s\n", clientCmdSTRING);
                                                         execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                         _exit(EXIT_FAILURE);
                                                         
                                                     } else if (strcmp(REMCtrl->actiontype, "USERDEFINED") == 0) {
                                                         /* Using compunded commands separated by ';'
                                                            3.1 validate existence of REMCtrl->actionsource and send 
                                                                its contents to target remote ip using pscp command 
                                                            3.2 launch REMCtrl->actionsource via plink command 
                                                                on remote target 
                                                          */

                                                         /* secure copy script to remote target, default to /home/[suerid]/ */
                                                         //strcpy(clientCmdSTRING, "echo '");
                                                         //strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                         //strcat(clientCmdSTRING, "' | ");

                                                         if ( strcmp(REMCtrl->isSudo, "1") == 0 ) {
                                                             strcpy(clientCmdSTRING, "echo '");
                                                             strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                             strcat(clientCmdSTRING, "' | sudo -S pscp -2 -l ");
                                                         } else
                                                             strcpy(clientCmdSTRING, "pscp -2 -l ");
                                                    
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, " -pw ");
                                                         strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                         strcat(clientCmdSTRING, " ");
                                                         strcat(clientCmdSTRING, REMCtrl->actionsource);   /* source */     
                                                         strcat(clientCmdSTRING, " ");
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, "@");
                                                         strcat(clientCmdSTRING, REMCtrl->targetip);
                                                         strcat(clientCmdSTRING, ":/home/");
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, "/remcv4tcpipl.sh; ");      /* separator ';' */
                                                         /* execute the copied script on the remote */
                                                         if ( strcmp(REMCtrl->isSudo, "1") == 0 ) {
                                                             strcat(clientCmdSTRING, "echo '");
                                                             strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                             strcat(clientCmdSTRING, "' | sudo -S plink -2 -l ");
                                                         } else
                                                             strcat(clientCmdSTRING, "plink -2 -l ");

                                                         strcat(clientCmdSTRING, "plink -2 -batch -l ");
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, " -pw ");
                                                         strcat(clientCmdSTRING, REMCtrl->targetpasswd);
                                                         strcat(clientCmdSTRING, " ");
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, "@");
                                                         strcat(clientCmdSTRING, REMCtrl->targetip);
                                                         strcat(clientCmdSTRING, " bash /home/");
                                                         strcat(clientCmdSTRING, REMCtrl->targetuserid);
                                                         strcat(clientCmdSTRING, "/remcv4tcpipl.sh 2>&1 | tee "); /* pipe the output to a file */
                                                         strcat(clientCmdSTRING, cv4home);
                                                         strcat(clientCmdSTRING, "/tmp/remotecontrol.txt");

                                                         //printf("--DEBUG-- (USERDEFINED)clientCmdSTRING:\n%s\n", clientCmdSTRING);
                                                         execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                         _exit(EXIT_FAILURE);
                                                     }
                                                     else if (child_pid < 0)
                                                         printf("Failed to execute plink command\n");
                                                 } else {
                                                     fprintf(stderr, "action does not validly support on this server\n");
                                                 }
                                             } else {
                                                 /* Send error message */ 
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
                                                 if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                     perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 //CmdSTRING = (char *) malloc(sizeof(char) * 1024);
                                                 memset(ExCmdSTRING, '\0', sizeof(1024));
                                                 strcpy(ExCmdSTRING, "INSERT INTO mobile_log(MonitorIP, UserID, ActionLabelSelected,");
                                                 strcat(ExCmdSTRING, "LastTargetNodeIP, ActionLabelLastRunDate, ActionLabelLastRunTime,");
                                                 strcat(ExCmdSTRING, " ActionLabelStatus) VALUES('");
                                                 strcat(ExCmdSTRING, MySQLSverIP);
                                                 strcat(ExCmdSTRING, "', '");
                                                 strcat(ExCmdSTRING, REMCtrl->targetuserid);
                                                 strcat(ExCmdSTRING, "', '");
                                                 strcat(ExCmdSTRING, REMCtrl->actionlabel);
                                                 strcat(ExCmdSTRING, "', '");
                                                 strcat(ExCmdSTRING, REMCtrl->targetip);
                                                 strcat(ExCmdSTRING, "', CURRENT_DATE(), CURRENT_TIME(), 'ERR') ON DUPLICATE KEY UPDATE ActionLabelLastRunDate = CURRENT_DATE(), ActionLabelLastRunTime = CURRENT_TIME(), ActionLabelStatus='ERR';");
//                                                 strcat(ExCmdSTRING, "', CURRENT_DATE(), CURRENT_TIME(), 'ERR') ON DUPLICATE KEY UPDATE ActionLabelLastRunDate = CURRENT_DATE(), ActionLabelLastRunTime = CURRENT_TIME(), ActionLabelStatus='ERR', StatusDescription='");
                                      
//                                                     tmpSTRING = (char *) malloc(rpyBuffer->RpyBufferLength);
//                                                     interSTRING = (char *) malloc(rpyBuffer->RpyBufferLength);
//                                                     strcpy(tmpSTRING, trim(rpyBuffer->Output));
//                                                     printf("Out=%s\n", tmpSTRING);
//                                                     strcpy(interSTRING, str_replace(tmpSTRING, "'", " "));
//                                                     printf("Out=%s\n", interSTRING);
//                                                     strcpy(tmpSTRING, str_replace(interSTRING, "`", " "));
//                                                     printf("Out=%s\n", tmpSTRING);
//                                                 strcat(CmdSTRING, tmpSTRING);
//                                                 strcat(CmdSTRING, "';");
                                                 //printf("--DEBUG-- UPDATE to mobile_log:\n%s\n", ExCmdSTRING);
                                                 strcpy(mysqlCommand->sqlcmdstmt, ExCmdSTRING);
                                                 mySQLexec(mysqlCommand);   /*-- send sqlstmt to database --*/
                                                      
                                                 free(rpyBuffer);  /* deallocate memory */
                                             }

                                             break;

                                        case CMD_REMOTECTRL_TEST_DIRECTIVE:
                                             /* Sanity check pass-in parameters */
                                             memset(str1, '\0', 14);
                                             memset(str2, '\0', 14);
                                             strncpy(str1, "plink", 5);  /* copy "plink" into str1 */
                                             strncpy(str2, clientCmdSTRING, 5);  /* copy first 7 characters of CmdString to str2 */
                                             /* test if str1 is identical to str2 */
                                             /* test if str1 is identical to str2 */
                                             if (strncmp(str2, str1, 5) != 0) {
                                                 //printf("DEBUG-- pass-in command %s is not a valid command.  Expected 'plink'\n", str2);
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 rpyBuffer->RpyBufferLength = 68;
                                                 rpyBuffer->ReturnCode = 1;
                                                 rpyBuffer->ReasonCode = 1;
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute remote command:  " );
                                                 strcat(rpyBuffer->Output, "\nUsage: plink [options] [user@]host [command] -m [script]\n");
                                                 strcat(rpyBuffer->Output, "e.g.     plink -2 -l userid -pw password host -m myscript.sh\n");

                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
                                                 if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                     perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */
                                             } else {
                                                /* Valid netstat command.  Let's boogie */
                                                 //printf("plink output:\n");
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
                                                    /* parent process */
                                                     waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                     //printf("DEBUG-- child_pid $d finished\n", child_pid);

                                                     /* send output back to client by accessing the file /var/log/cv4log/netstatout1.txt */
                                                     /* allocate memory for struct RpyRealtime_t */
                                                     rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                     memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/remotecontrol.txt");
                                                     /*totalbytes =  getOutputFromFile("/tmp/remotecontrol.txt",  buf);*/
                                                     totalbytes =  getOutputFromFile(filename,  buf);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->RpyBufferLength = totalbytes;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) {
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 4;
                                                         strcpy(rpyBuffer->Output, "Failed to execute netstat command:  ");
                                                         strcat(rpyBuffer->Output, clientCmdSTRING);
                                                         strcat(rpyBuffer->Output, "\nUsage: plink [options] [user@]host [command] -m [script]\n");
                                                         strcat(rpyBuffer->Output, "e.g.     plink -2 -l userid -pw password host -m myscript.sh\n");
                                                         rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                     } else {
                                                         strcpy(filename, cv4home);
                                                         strcat(filename, "/tmp/remotecontrol.txt");
                                                         /*FILE *fp=fopen("/tmp/remotecontrol.txt", "rb");*/
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                         rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                     }
                                                     /*remove("/tmp/remotecontrol.txt");*/
                                                     remove(filename);
                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                     /* send output back to sender */
                                                     if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                         perror("send() error!");

                                                     //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                     free(rpyBuffer);  /* deallocate memory */
                                                 } else if (child_pid == 0) {
                                                     /* this is the child netstat process. */
                                                     strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                     strcat(clientCmdSTRING, cv4home);
                                                     strcat(clientCmdSTRING, "/tmp/remotecontrol.txt; sleep 1");
                                                     execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                     _exit(EXIT_FAILURE);
                                                 }
                                                 else if (child_pid < 0)
                                                     printf("Failed to execute plink command\n");
                                             }
					     break;

				        case CMD_NETSTAT_DIRECTIVE:
                                             /* Sanity check pass-in parameters */
                                             memset(str1, '\0', 14);
                                             memset(str2, '\0', 14);
                                             strncpy(str1, "snmpnetstat", 11);  /* copy "netstat" into str1 */
                                             strncpy(str2, clientCmdSTRING, 11);  /* copy first 7 characters of CmdString to str2 */
                                             /* test if str1 is identical to str2 */
                                             if (strncmp(str2, str1, 11) != 0) {
                                                 printf("DEBUG-- pass-in command %s is not a valid command.  Expected 'snmpnetstat'\n", str2);
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 rpyBuffer->RpyBufferLength = 68;
                                                 rpyBuffer->ReturnCode = 1;
                                                 rpyBuffer->ReasonCode = 1;
                                                 rpyBuffer->RpyEntries = 4;
                                                 strcpy(rpyBuffer->Output, "Failed to execute snmpnetstat command:  " );
                                                 strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                 strcat(rpyBuffer->Output, "\nUsage: netstat [-veenNcCF] [<Af>] -r         netstat {-V|--version|-h|--help}\n");
                                                 strcat(rpyBuffer->Output, "       snmpnetstat [-vnNcaeol] [<Socket> ...]\n");
                                                 strcat(rpyBuffer->Output, "       snmpnetstat { [-veenNac] -I[<Iface>] | [-veenNac] -i | [-cnNe] -M | -s } [delay]\n");

                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else {
                                                 /* Valid netstat command.  Let's bugie */
					         printf("snmpnetstat output:\n");
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
                                                    /* parent process */
                                                     waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                     //printf("DEBUG-- child_pid $d finished\n", child_pid); 
                        
                                                     /* send output back to client by accessing the file /var/log/cv4log/netstatout1.txt */
                                                     /* allocate memory for struct RpyRealtime_t */
                                                     rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                     memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/netstatout1.txt");
                                                     /*totalbytes =  getOutputFromFile("/tmp/netstatout1.txt",  buf);*/
                                                     totalbytes =  getOutputFromFile(filename,  buf);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->RpyBufferLength = totalbytes;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) { 
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 4;
                                                         strcpy(rpyBuffer->Output, " ");
//                                                         strcpy(rpyBuffer->Output, "Failed to execute snmpnetstat command:  ");
//                                                         strcat(rpyBuffer->Output, clientCmdSTRING); 
//                                                         strcat(rpyBuffer->Output, "\nUsage: snmpnetstat [-veenNcCF] [<Af>] -r         netstat {-V|--version|-h|--help}\n");
//                                                         strcat(rpyBuffer->Output, "       snmpnetstat [-vnNcaeol] [<Socket> ...]\n");
//                                                         strcat(rpyBuffer->Output, "       snmpnetstat { [-veenNac] -I[<Iface>] | [-veenNac] -i | [-cnNe] -M | -s } [delay]\n");
                                                         rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                     } else {
                                                         strcpy(filename, cv4home);
                                                         strcat(filename, "/tmp/netstatout1.txt");
                                                         /*FILE *fp=fopen("/tmp/netstatout1.txt", "rb");*/
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                         rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                     } 
                                                     /*remove("/tmp/netstatout1.txt");*/
                                                     remove(filename);
                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                     /* send output back to sender */
			                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                                 perror("send() error!");
                      
                                                     printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     printf("Contents:\n%s\n", rpyBuffer->Output);
                                                     free(rpyBuffer);  /* deallocate memory */                    
                                                 } else if (child_pid == 0) {
                                                     /* this is the child netstat process. */
                                                     strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                     strcat(clientCmdSTRING, cv4home);
                                                     strcat(clientCmdSTRING, "/tmp/netstatout1.txt; sleep 1");
                                                     execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                     _exit(EXIT_FAILURE);
                                                 }
                                                 else if (child_pid < 0)
                                                     printf("Failed to execute netstat command\n");
                                             }
					     break;
				        case CMD_NSLOOKUP_DIRECTIVE:
                                             /* Sanity check pass-in parameters */
                                             memset(str1, '\0', 14);
                                             memset(str2, '\0', 14);
                                             strncpy(str1, "nslookup", 8);  /* copy "nslookup" into str1 */
                                             strncpy(str2, clientCmdSTRING, 8);  /* copy first 8 characters of CmdString to str2 */
                                             /* test if str1 is identical to str2 */
                                             if (strncmp(str2, str1, 8) != 0) {
                                                 //printf("DEBUG-- pass-in command %s is not a valid command.  Expected 'nslookup'\n", str2);
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * SMALL_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 rpyBuffer->RpyBufferLength = 69;
                                                 rpyBuffer->ReturnCode = 1;
                                                 rpyBuffer->ReasonCode = 1;
                                                 rpyBuffer->RpyEntries = 3;
                                                 strcpy(rpyBuffer->Output, "Failed to execute nslookup command:  " );
                                                 strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                 strcat(rpyBuffer->Output, "\nUsage:\n");
                                                 strcat(rpyBuffer->Output, "    nslookup [-option] [name | -] [server]\n");

                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else {
                                                 /* Valid netstat command.  Let's bugie */
					         //printf("nslookup output:\n");
                                                 child_pid = fork();
                                                 if (child_pid > 0) {
                                                     /* parent process */
                                                     waitpid(child_pid, 0, 0);                       /* wait until child process finished */

                                                     //printf("DEBUG-- child_pid %d finished\n", child_pid); 
                        
                                                     /* send output back to client by accessing the file /var/log/cv4log/pingout.txt */
                                                     /* allocate memory for struct RpyRealtime_t */
                                                     rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                     memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/nslookupout.txt");
                                                     /*totalbytes =  getOutputFromFile("/tmp/nslookupout.txt",  buf);*/
                                                     totalbytes =  getOutputFromFile(filename,  buf);
                                                     rpyBuffer->ReturnCode = 0;
                                                     rpyBuffer->ReasonCode = 0;
                                                     rpyBuffer->RpyBufferLength = totalbytes;
                                                     rpyBuffer->ProdCode = PRODUCTCODE;
                                                     if (totalbytes == 0) { 
                                                         rpyBuffer->ReturnCode = 1;
                                                         rpyBuffer->ReasonCode = 1;
                                                         rpyBuffer->RpyEntries = 3;
                                                         strcpy(rpyBuffer->Output, "Failed to execute nslookup command:  " );
                                                         strcat(rpyBuffer->Output, clientCmdSTRING); 
                                                         strcat(rpyBuffer->Output, "\nUsage:\n");
                                                         strcat(rpyBuffer->Output, "    nslookup [-option] [name | -] [server]\n");
                                                         rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                     } else {
                                                         strcpy(filename, cv4home);
                                                         strcat(filename, "/tmp/nslookupout.txt");
                                                         /*FILE *fp=fopen("/tmp/nslookupout.txt", "rb");*/
                                                         FILE *fp=fopen(filename, "rb");
                                                         rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                         strncpy(rpyBuffer->Output, buf, totalbytes);
                                                         fclose(fp);
                                                         rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                     } 
                                                     /*remove("/tmp/nslookupout.txt");*/
                                                     remove(filename);
                                                     /* Convert to network byte order */
                                                     rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                     rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                     rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                     rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                     rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                     /* send output back to sender */
			                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                                 perror("send() error!");
                                      
                                                     //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                     //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                     free(rpyBuffer);  /* deallocate memory */                    
                                                 } else if (child_pid == 0) {
                                                     /* this is the child nslookup process. */
                                                     strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                     strcat(clientCmdSTRING, cv4home);
                                                     strcat(clientCmdSTRING, "/tmp/nslookupout.txt; sleep 1");
                                                     execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                     _exit(EXIT_FAILURE);
                                                 }
                                                 else if (child_pid < 0)
                                                     printf("Failed to execute nslookup command\n");
                                             }
					     break;

				        case CMD_PORT_STATUS_DIRECTIVE:
					     printf("port status output:\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */

                                                 /* send output back to client by accessing the file /var/log/cv4log/portmonout.txt */
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/portmonout.txt");
                                                 /*totalbytes =  getOutputFromFile("/tmp/portmonout.txt",  buf);*/
                                                 totalbytes =  getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = totalbytes;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) { 
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to execute portmon command");
                                                     rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 } else {
                                                     /*FILE *fp=fopen("/tmp/portmonout.txt", "rb");*/
                                                     FILE *fp=fopen(filename, "rb");
                                                     rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                     strncpy(rpyBuffer->Output, buf, totalbytes);
                                                     fclose(fp);
                                                     rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                 } 
                                                 /*remove("/tmp/portmonout.txt");*/
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");
                                      
                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else if (child_pid == 0) {
                                                 /* this is the child portmon process. */
                                                 strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                 strcat(clientCmdSTRING, cv4home);
                                                 strcat(clientCmdSTRING, "/tmp/portmonout.txt; sleep 1");
                                                 execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                 _exit(EXIT_FAILURE);
                                             }
                                             else if (child_pid < 0)
                                                  printf("Failed to execute portmon command\n");
					     break;
				        case CMD_ALL_PORT_STATUS_DIRECTIVE:
					     //printf("all ports output:\n");
                                             child_pid = fork();
                                             if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */

                                                 //printf("DEBUG-- child_pid %d finished\n", child_pid); 
                        
                                                 /* send output back to client by accessing the file /var/log/cv4log/portscanout.txt */
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * BIG_RPYBUFFLEN);
                                                 memset(rpyBuffer->Output, '\0', sizeof(1024));
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/portscanout.txt");
                                                 /*totalbytes =  getOutputFromFile("/tmp/portscanout.txt",  buf);*/
                                                 totalbytes =  getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = totalbytes;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) { 
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 1;
                                                     strcpy(rpyBuffer->Output, "Failed to execute portscan command");
                                                     rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 } else {
                                                     /*FILE *fp=fopen("/tmp/portscanout.txt", "rb");*/
                                                     FILE *fp=fopen(filename, "rb");
                                                     rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                     strncpy(rpyBuffer->Output, buf, totalbytes);
                                                     fclose(fp);
                                                     rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                 } 
                                                 /*remove("/tmp/portscanout.txt");*/
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                 /* send output back to sender */
			                         if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                             perror("send() error!");
                                      
                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */                    
                                             } else if (child_pid == 0) {
                                                 /* this is the child portscan process. */
                                                 strcat(clientCmdSTRING, " 2>&1 | tee ");
                                                 strcat(clientCmdSTRING, cv4home);
                                                 strcat(clientCmdSTRING, "/tmp/portscanout.txt; sleep 1");
                                                 execl(SHELL, SHELL, "-c", clientCmdSTRING, NULL);
                                                 _exit(EXIT_FAILURE);
                                             }
                                             else if (child_pid < 0)
                                                  printf("Failed to execute portscan command\n");
					     break;
                                        }
				        break;

                                    case CMDCODE_CONNEXP_TCP_LSTRS:    /* 0x4006 -- Realtime connect expert TCP listeners */
                                         /* Sanity check pass-in parameters */
                                         /* test if node ip was specified */
                                         if (strlen(clientCmdSTRING) == 0) {
                                             //printf("DEBUG-- Expected node IP address not found.\n", str2);
                                             /* allocate memory for struct RpyRealtime_t */
                                             rpyBuffer = (RpyHeader_t *) malloc(SMALL_RPYBUFFLEN);
                                             strncpy(rpyBuffer->Output, "", 1000);
                                             rpyBuffer->ProdCode = PRODUCTCODE;
                                             rpyBuffer->RpyBufferLength = 47;
                                             rpyBuffer->ReturnCode = 1;
                                             rpyBuffer->ReasonCode = 1;
                                             rpyBuffer->RpyEntries = 1;
                                             strcpy(rpyBuffer->Output, "Expected Node IP address not found." );

                                             rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                             /* Convert to network byte order */
                                             rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                             rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                             rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                             rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                             rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                             /* send output back to sender */
                                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                 perror("send() error!");

                                             //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                             //printf("Contents:\n%s\n", rpyBuffer->Output);
                                             free(rpyBuffer);  /* deallocate memory */
                                         } else {
                                             /* Valid node ip address found.  Let's bugie */
                                             /* printf("connect expert TCP listeners for node %s\n", clientCmdSTRING); */
                                             child_pid = fork();
                                             if (child_pid == 0) {
                                                 /* this is the child tcplisteners process. */
                                                 /* entire command string:
                                                    "snmpnetstat -v2c -cpublic 137.72.43.204 -Can -Cp tcp
                                                     | grep LISTEN > /tmp/tcplistners.txt;
                                                     /usr/sbin/cv4parsetcudp /tmp/tcplisteners.txt tcp
                                                 */
                                                 strcpy(NodeIP, clientCmdSTRING);
                                                 strcpy(CommunitySTRING, getDataField(MySQLSverIP, NodeIP, 1));

                                                 strcpy(ExCmdSTRING, "snmpnetstat -v2c -c");
                                                 strcat(ExCmdSTRING, CommunitySTRING);
                                                 strcat(ExCmdSTRING, " ");
                                                 strcat(ExCmdSTRING, NodeIP);
                                                 //strcat(ExCmdSTRING, " -Can -Cp tcp | grep LISTEN > ");
                                                 strcat(ExCmdSTRING, " -Can -Cp tcp > ");
                                                 strcat(ExCmdSTRING, cv4home);
                                                 strcat(ExCmdSTRING, "/tmp/tcplisteners.txt; /usr/sbin/cv4parsetcudp ");
                                                 strcat(ExCmdSTRING, cv4home);
                                                 strcat(ExCmdSTRING, "/tmp/tcplisteners.txt tcp");
//snmpnetstat -v2c -cpublic 137.72.43.122 -Can -Cp tcp | grep LISTEN > netstatout.txt && netstat -nat | grep LISTEN >> netstatout.txt
                                                 //printf("STMT: %s\n", ExCmdSTRING);
                                                 execl(SHELL, SHELL, "-c", ExCmdSTRING, NULL);
                                                 _exit(EXIT_FAILURE);

                                             } else if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);      /* wait until child process finished */

                                                 /* send output back to client by accessing the file /var/log/cv4log/tcplisteners.txt */
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/tcplisteners.txt");

                                                 INTERMEDIATE_FSIZE = get_file_size(filename);
                                                 if (INTERMEDIATE_FSIZE > 0)
                                                     rpyBuffer = (RpyHeader_t *) malloc(INTERMEDIATE_FSIZE + 64);
                                                 else
                                                     rpyBuffer = (RpyHeader_t *) malloc(BIG_RPYBUFFLEN);

                                                 totalbytes = getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = totalbytes;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) {
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 2;
                                                     strcpy(rpyBuffer->Output, "Empty output for command 'snmpnetstat -v2c -c<community> ");
                                                     strcat(rpyBuffer->Output, clientCmdSTRING);
                                                     strcat(rpyBuffer->Output, " -Can -Cp tcp && netstat -nat | grep LISTEN'\nPlease make sure snmpd is active on ");
                                                     strcat(rpyBuffer->Output, clientCmdSTRING);
                                                     strcat(rpyBuffer->Output, ".");
                                                 } else {
                                                     /*FILE *fp=fopen("/tmp/tcplisteners.txt", "rb");*/
                                                     FILE *fp=fopen(filename, "rb");
                                                     rpyBuffer->RpyEntries = linecount(fp, 2000);
                                                     strncpy(rpyBuffer->Output, buf, totalbytes);
                                                     fclose(fp);
                                                 }
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /*remove("/tmp/tcplisteners.txt");*/
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
                                                 if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                     perror("send() error!");

                                                 //printf("TCP Listener -- Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */
                                             } else if (child_pid < 0)
                                                 printf("Failed to get tcp listeners using snmpnetstat command.\n");
                                        }
                                        break;

                                   case CMDCODE_CONNEXP_UDP_LSTRS:    /* 0x4007 -- Realtime connect expert UDP Endpoint */
                                        /* Sanity check pass-in parameters */
                                        /* test if node ip was specified */
                                        if (strlen(clientCmdSTRING) == 0) {
                                             //printf("DEBUG-- Expected node IP address not found.\n", str2);
                                             /* allocate memory for struct RpyRealtime_t */
                                             rpyBuffer = (RpyHeader_t *) malloc(SMALL_RPYBUFFLEN);
                                             strncpy(rpyBuffer->Output, "", 1000);
                                             rpyBuffer->ProdCode = PRODUCTCODE;
                                             rpyBuffer->RpyBufferLength = 47;
                                             rpyBuffer->ReturnCode = 1;
                                             rpyBuffer->ReasonCode = 1;
                                             rpyBuffer->RpyEntries = 1;
                                             strcpy(rpyBuffer->Output, "Expected Node IP address not found." );
                                             rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                             /* Convert to network byte order */
                                             rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                             rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                             rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                             rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                             rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                             /* send output back to sender */
                                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                 perror("send() error!");

                                             //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                             //printf("Contents:\n%s\n", rpyBuffer->Output);
                                             free(rpyBuffer);  /* deallocate memory */
                                        } else {
                                            //printf("connect expert UDP EndPoints on monitor host.\n");
                                            child_pid = fork();
                                            if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);                       /* wait until child process finished */

                                                 //printf("DEBUG-- child_pid %d finished\n", child_pid);

                                                 /* send output back to client by accessing the file /var/log/cv4log/udpendpoints.txt */
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/udpendpoints.txt");

                                                 INTERMEDIATE_FSIZE = get_file_size(filename);
                                                 if (INTERMEDIATE_FSIZE > 0)
                                                     rpyBuffer = (RpyHeader_t *) malloc(INTERMEDIATE_FSIZE + 64);
                                                 else
                                                     rpyBuffer = (RpyHeader_t *) malloc(BIG_RPYBUFFLEN);

                                                 totalbytes =  getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = totalbytes;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) {
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 2;
                                                     strcpy(rpyBuffer->Output, "Failed to execute command 'snmpnetstat -v2c -c<community> ");
                                                     strcat(rpyBuffer->Output, clientCmdSTRING);
                                                     strcat(rpyBuffer->Output, " -Can -Cp udp'\nPlease make sure snmpd is active on ");
                                                     strcat(rpyBuffer->Output, clientCmdSTRING);
                                                     strcat(rpyBuffer->Output, ".");
                                                 } else {
                                                     strcpy(filename, cv4home);
                                                     strcat(filename, "/tmp/udpendpoints.txt");
                                                     /*FILE *fp=fopen("/tmp/udpendpoints.txt", "rb");*/
                                                     FILE *fp=fopen(filename, "rb");
                                                     rpyBuffer->RpyEntries = linecount(fp, 1000);
                                                     strncpy(rpyBuffer->Output, buf, totalbytes);
                                                     fclose(fp);
                                                 }
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 /*remove("/tmp/udpendpoints.txt");*/
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
                                                 if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                     perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */
                                            } else if (child_pid == 0) {
                                                 /* this is the child udpendpoints process. */
                                                 strcpy(NodeIP, clientCmdSTRING);
                                                 strcpy(CommunitySTRING, getDataField(MySQLSverIP, clientCmdSTRING, 1));
                                                 memset(ExCmdSTRING, '\0', sizeof(1024));
                                                 strcpy(ExCmdSTRING, "snmpnetstat -v2c -c");
                                                 strcat(ExCmdSTRING, CommunitySTRING);
                                                 strcat(ExCmdSTRING, " ");
                                                 strcat(ExCmdSTRING, NodeIP);
                                                 //strcat(ExCmdSTRING, " -Can -Cp udp | grep udp > ");
                                                 strcat(ExCmdSTRING, " -Can -Cp udp > ");
                                                 strcat(ExCmdSTRING, cv4home);
                                                 strcat(ExCmdSTRING, "/tmp/udpendpoints.txt; /usr/sbin/cv4parsetcudp ");
                                                 strcat(ExCmdSTRING, cv4home);
                                                 strcat(ExCmdSTRING, "/tmp/udpendpoints.txt udp");

                                                 //printf("STMT: %s\n", ExCmdSTRING);
                                                 execl(SHELL, SHELL, "-c", ExCmdSTRING, NULL);
                                                 _exit(EXIT_FAILURE);
                                            }
                                            else if (child_pid < 0)
                                                 printf("Failed to get udp endpoints\n");
                                        }
                                        break;

                                   case CMDCODE_CONNEXP_CONNECTIONS:    /* 0x4008 -- Realtime connect expert TCP connections */
                                        /* Sanity check pass-in parameters */
                                        /* test if node ip was specified */
                                        if (strlen(clientCmdSTRING) == 0) {
                                             //printf("DEBUG-- Expected node IP address not found.\n", str2);
                                             /* allocate memory for struct RpyRealtime_t */
                                             rpyBuffer = (RpyHeader_t *) malloc(BIG_RPYBUFFLEN);
                                             strncpy(rpyBuffer->Output, "", 1000);
                                             rpyBuffer->ProdCode = PRODUCTCODE;
                                             rpyBuffer->RpyBufferLength = 47;
                                             rpyBuffer->ReturnCode = 1;
                                             rpyBuffer->ReasonCode = 1;
                                             rpyBuffer->RpyEntries = 2;
                                             strcpy(rpyBuffer->Output, "Failed to execute command 'snmpwalk -Osq -v2c -c<community> ");
                                             strcat(rpyBuffer->Output, clientCmdSTRING);
                                             strcat(rpyBuffer->Output, " tcpConnState'\nPlease make sure snmpd is active on this selected node.");
                                             rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                             /* Convert to network byte order */
                                             rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                             rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                             rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                             rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                             rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                             /* send output back to sender */
                                             if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                 perror("send() error!");

                                             //printf("TCP Connections -- Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                             //printf("Contents:\n%s\n", rpyBuffer->Output);
                                             free(rpyBuffer);  /* deallocate memory */
                                        } else {
                                            //printf("connect expert TCP Connections.\n");
                                            child_pid = fork();
                                            if (child_pid > 0) {
                                                 /* parent process */
                                                 waitpid(child_pid, 0, 0);     /* wait until child process finished */

                                                 //printf("DEBUG-- TCP Connections child_pid %d finished\n", child_pid);

                                                 /* send output back to client by accessing the file /var/log/cv4log/tcpconnections.txt */
                                                 /* allocate memory for struct RpyRealtime_t */
                                                 strcpy(filename, cv4home);
                                                 strcat(filename, "/tmp/tcpconnections.txt");
                                                 INTERMEDIATE_FSIZE = get_file_size(filename);

                                                 if (INTERMEDIATE_FSIZE > 0)
                                                     rpyBuffer = (RpyHeader_t *) malloc(INTERMEDIATE_FSIZE + 64);
                                                 else
                                                     rpyBuffer = (RpyHeader_t *) malloc(BIG_RPYBUFFLEN);

                                                 totalbytes =  getOutputFromFile(filename,  buf);
                                                 rpyBuffer->ReturnCode = 0;
                                                 rpyBuffer->ReasonCode = 0;
                                                 rpyBuffer->RpyBufferLength = totalbytes;
                                                 rpyBuffer->ProdCode = PRODUCTCODE;
                                                 if (totalbytes == 0) {
                                                     rpyBuffer->ReturnCode = 1;
                                                     rpyBuffer->ReasonCode = 1;
                                                     rpyBuffer->RpyEntries = 2;
                                                     strcpy(rpyBuffer->Output, "Empty output resulted when executed command 'snmpwalk -Osq -v2c -c<community> ");
                                                     strcat(rpyBuffer->Output, clientCmdSTRING);
                                                     strcat(rpyBuffer->Output, " tcpConnState'\nPlease check with system administrator if this is correct for selected node.");
                                                     rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 } else {
                                                     /*FILE *fp=fopen("/tmp/tcpconnections.txt", "rb");*/
                                                     FILE *fp=fopen(filename, "rb");
                                                     rpyBuffer->RpyEntries = linecount(fp, 4000);
                                                     strncpy(rpyBuffer->Output, buf, totalbytes);
                                                     fclose(fp);
                                                     rpyBuffer->RpyBufferLength = totalbytes + RPYHEADERLEN;
                                                 }
                                                 rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                 //remove("/tmp/tcpconnections.txt");
                                                 remove(filename);
                                                 /* Convert to network byte order */
                                                 rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                 rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                 rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                 rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                 rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);

                                                 /* send output back to sender */
                                                 if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
                                                    perror("send() error!");

                                                 //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                 //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                 free(rpyBuffer);  /* deallocate memory */
                                           } else if (child_pid == 0) {
                                                /* this is the child tcp connections process. */
                                                 strcpy(NodeIP, clientCmdSTRING);
                                                 strcpy(CommunitySTRING, getDataField(MySQLSverIP, clientCmdSTRING, 1));
                                                 memset(ExCmdSTRING, '\0', sizeof(1024));
                                                 strcpy(ExCmdSTRING, "snmpwalk -Osq -v2c -c");
                                                 strcat(ExCmdSTRING, CommunitySTRING);
                                                 strcat(ExCmdSTRING, " ");
                                                 strcat(ExCmdSTRING, NodeIP);
                                                 //strcat(ExCmdSTRING, " tcpConnState | grep timeWait > ");
                                                 //strcat(ExCmdSTRING, " 1.3.6.1.2.1.6.13.1.1 | grep timeWait > ");
                                                 strcat(ExCmdSTRING, " 1.3.6.1.2.1.6.13.1.1 > ");
                                                 strcat(ExCmdSTRING, cv4home);
                                                 strcat(ExCmdSTRING, "/tmp/tcpconnections.txt; sleep 1; /usr/sbin/cv4parseconn ");
                                                 strcat(ExCmdSTRING, cv4home);
                                                 strcat(ExCmdSTRING, "/tmp/tcpconnections.txt; sleep 1");
                                                 //printf("STMT: %s\n", ExCmdSTRING);
                                                 execlp(SHELL, SHELL, "-c", ExCmdSTRING, NULL);
                                                 _exit(EXIT_FAILURE);


                                                /* this is the child tcp connections process. */
//                                                 strcpy(NodeIP, clientCmdSTRING);
//                                                 strcpy(CommunitySTRING, getDataField(MySQLSverIP, clientCmdSTRING, 1));
//                                                 memset(ExCmdSTRING, '\0', sizeof(1024));
//                                                 strcpy(ExCmdSTRING, "snmpnetstat -v2c -c");
//                                                 strcat(ExCmdSTRING, CommunitySTRING);
//                                                 strcat(ExCmdSTRING, " ");
//                                                 strcat(ExCmdSTRING, NodeIP);
//                                                 //strcat(ExCmdSTRING, " tcpConnState | grep timeWait > ");
//                                                 //strcat(ExCmdSTRING, " 1.3.6.1.2.1.6.13.1.1 | grep timeWait > ");
//                                                 strcat(ExCmdSTRING, " -Can -Cp tcp > ");
//                                                 strcat(ExCmdSTRING, cv4home);
//                                                 strcat(ExCmdSTRING, "/tmp/tcpconnections.txt; sleep 1; /usr/sbin/cv4parseconn ");
//                                                 strcat(ExCmdSTRING, cv4home);
//                                                 strcat(ExCmdSTRING, "/tmp/tcpconnections.txt; sleep 1");
//                                                 //printf("STMT: %s\n", ExCmdSTRING);
//                                                 execlp(SHELL, SHELL, "-c", ExCmdSTRING, NULL);
//                                                 _exit(EXIT_FAILURE);

                                           }
                                           else if (child_pid < 0)
                                                 printf("Failed to execute tcp connections (snmpwalk -Osq -v2c -c<community> tcpConnState) command\n");
                                       }
                                       break;




				   case CMDCODE_DEBUG_LOG:    /* 0x4010 -- Debugging by uploading monitor logs */
			  	       switch(revcBuffer->CmdDirective) {
				           case CMD_UPLOAD_DIRECTIVE:
                                               /* this block of code is use to upload monitoring log onto a designated */
                                               /* website for debugging purpose only */
                                               child_pid = fork();
                                               if (child_pid > 0) {
                                                    /* parent process */
                                                    waitpid(child_pid, 0, 0);                       /* wait until child process finished */
                                                    //printf("DEBUG-- child_pid %d finished\n", child_pid); 
                         
                                                    /* allocate memory for struct RpyRealtime_t */
                                                    rpyBuffer = (RpyHeader_t *) malloc(sizeof(RpyHeader_t) * MAXRPYBYTES);
                                                    strcpy(rpyBuffer->Output, "");
                                                    //totalbytes =  getOutputFromFile("/var/log/cv4log/monitor.log",  buf);
                                                    rpyBuffer->ReturnCode = 0;
                                                    rpyBuffer->ReasonCode = 0;
                                                    //rpyBuffer->RpyBufferLength = totalbytes;
                                                    rpyBuffer->RpyBufferLength = 112;
                                                    rpyBuffer->ProdCode = PRODUCTCODE;
                                                    if (totalbytes == 0) { 
                                                        rpyBuffer->ReturnCode = 1;
                                                        rpyBuffer->ReasonCode = 1;
                                                        rpyBuffer->RpyEntries = 1;
                                                        strcpy(rpyBuffer->Output, "Failed to get monitor.log");
                                                    } else {
                                                        rpyBuffer->RpyEntries = 1;
                                                        strcpy(rpyBuffer->Output, "Monitor log has been uploaded to http://www.aesclever.com/aftp/.cleversoft/.greenprj/monitor_log.txt");
                                                    } 
                                                    rpyBuffer->RpyBufferLength = strlen(rpyBuffer->Output) + RPYHEADERLEN;
                                                    /* Convert to network byte order */
                                                    rpyBuffer->ReturnCode = htons(rpyBuffer->ReturnCode);
                                                    rpyBuffer->ReasonCode = htons(rpyBuffer->ReasonCode);
                                                    rpyBuffer->RpyBufferLength = htonl(rpyBuffer->RpyBufferLength);
                                                    rpyBuffer->ProdCode = htonl(PRODUCTCODE);
                                                    rpyBuffer->RpyEntries = htons(rpyBuffer->RpyEntries);
                                                 
                                                   /* send output back to sender */
			                           if(send(i, rpyBuffer, ntohl(rpyBuffer->RpyBufferLength), 0) == -1)
			                               perror("send() error!");
                                      
                                                    //printf("Replied with %d bytes\n", ntohl(rpyBuffer->RpyBufferLength));
                                                    //printf("Contents:\n%s\n", rpyBuffer->Output);
                                                    free(rpyBuffer);  /* deallocate memory */                    
                                              } else if (child_pid == 0) {
                                                   /* this is the child file uploading process. */
                                                   execl(SHELL, SHELL, "-c", ".uploadlog", NULL);
                                                   _exit(EXIT_FAILURE);
                                              }
                                              else if (child_pid < 0)
                                                    printf("Failed to process file upload command\n");
                                               
                                               break;
                                       }
                                       break;
			           } /*end switch CMDCODE_xxx_MONITOR*/

                                }/* endif ProdCode == 0xABBABABE found */

		                /* force close sender's connection */
		                close(i);

		                /* remove from master set */
		                FD_CLR(i, &master);
		            }/* endif received byte from ctrlCmdHeader_t */ 
		        }
                    }/*end ProdCode==0xABBABABE*/
               } /*end else*/
     }
     close(cres_fd);		        /* Close redirected output */
     close(defout);
     return 0;
}


