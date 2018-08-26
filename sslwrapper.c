/*---------------------------------------------------------------------------------*
 * Intellectual property of Applied Expert Systems, Inc.
 * Copyrights 2011 
 * Description: Wrapper for cv4tcpipl monitoring encrypted shell scripts.
 *              shell scripts are deployed encrypted using openssl.  In order to launch
 *              the script, it is first decrypted, changed +x and launched.
 *              scripts are encrypted using aes-128-ecb 
 *              e.g.
 *              Encrypt:
 *                 openssl enc -aes-128-ecb -salt -in $CV4_HOME/.cvCRES -out ./.cv4CRES.enc -pass pass:roland1
 *              Decrypt:
 *                 openssl enc -d -aes-128-ecb -salt -in ./.cvCRES.enc -out $CV4_HOME/.cv4CRES -pass pass:roland1
 *  Author: Mark Nguyen
 *  Conception: 04-05-2011
 *  Sypnosis: cv4monwrapper -s CRES
 *            sudo ./cv4monwrapper -s PORT
 *            sudo ./cv4monwrapper -r node
 *---------------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#define SHELL       "/bin/sh"      /* system shell command */
//#define LOG                        /* write to log if defined */


int run_my_script (const char *command) {
   int status;
   pid_t pid;
     
   pid = fork ();
   if (pid == 0) {
      /* This is the child process.  Execute the shell command. */
      execl (SHELL, SHELL, "-c", command, NULL);
      _exit (EXIT_FAILURE);
   }
   else if (pid < 0)
      /* The fork failed.  Report failure.  */
      status = -1;
   else
      /* This is the parent process.  Wait for the child to complete.  */
      if (waitpid (pid, &status, 0) != pid)
         status = -1;
   return status;
}


/* To shorten example, not using argp */
int main (int argc, char *argv[], char *envp[])
{
  char *home, *host, *cv4home;
  char *startuppath = (char *) malloc (100);
  char *fullpathtofile = (char *) malloc (100);
  char *cmdstr = (char *) malloc (254);
  FILE *fp;
  int sflag = 0;  /* start */
  int eflag = 0;  /* stop */
  int rflag = 0;  /* restart */
  int dflag = 0;  /* decode */
  char *cvalue = NULL;  /* expect optarg == {CRES, PORT, NODE} */
  int c;
     
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
  printf ("CV4_HOME=%s\n", cv4home);
  opterr = 0;

  while ((c = getopt (argc, argv, "s:e:r:d:")) != -1)
  switch (c)
  {
     case 'd': /* -d == decode a file */
               /* expect syntax: cv4monwrapper -d dbase */
        dflag = 1;
        cvalue = optarg;
        if (argc > 1) {
            if (strcmp(cvalue, "dbase") == 0 || strcmp(cvalue, "DBASE") == 0) {
                /* decode the pass-in script file.  expected an encripted file.  i am not checking that for you. */
                memset(cmdstr, '\0', sizeof(254));
                strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/dbase/createmonitordbase.enc -out ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/dbase/.createmonitordbase.sh -pass pass:roland1"); 
                if (run_my_script (cmdstr) == -1)
                   fprintf(stderr, "Failed to decrypt specified file %s/dbase/createmonitordbase.sh\n", cv4home);
                 
                strcpy(cmdstr, "chmod 555 ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/dbase/.createmonitordbase.sh");
                if (run_my_script (cmdstr) == -1)
                   fprintf(stderr, "Failed to chmod decrypted file %s/dbase/createmonitordbase.sh\n", cv4home);
                free(cmdstr);
            } 
            
            if (strcmp(cvalue, "ssql") == 0 || strcmp(cvalue, "SSQL") == 0) {
                /* decode the pass-in script file.  expected an encripted file.  i am not checking that for you. */
                memset(cmdstr, '\0', sizeof(254));
                strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/dbase/stored-programs.enc -out ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/dbase/stored-programs.sql -pass pass:roland1"); 
                if (run_my_script (cmdstr) == -1)
                   fprintf(stderr, "Failed to decrypt specified file %s/dbase/stored-programs.sql\n", cv4home);
                 
                free(cmdstr);
            } 
            if (strcmp(cvalue, "schema") == 0 || strcmp(cvalue, "SCHEMA") == 0) {
                /* decode the pass-in script file.  expected an encripted file.  i am not checking that for you. */
                memset(cmdstr, '\0', sizeof(254));
                strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/dbase/dbaselinuxmaster.enc -out ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/dbase/dbaselinuxmaster.txt -pass pass:roland1"); 
                if (run_my_script (cmdstr) == -1)
                   fprintf(stderr, "Failed to decrypt specified file %s/dbase/dbaselinuxmaster.txt\n", cv4home);
                 
                free(cmdstr);
            } 
        }
        break;
     case 's': /* -s == start script */
               /* expect syntax: cv4monwrapper -s {cres|port|node|kvm} */
        sflag = 1;
        cvalue = optarg;
        if (argc > 1) {
            if (strcmp(cvalue, "KVM") == 0 || strcmp(cvalue, "kvm") == 0) {
                /* Check if core file exists */
                memset(fullpathtofile, '\0', sizeof(100));
                strcpy(fullpathtofile, cv4home);
                strcat(fullpathtofile, "/.cv4KVM.enc"); 
                if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                    /*
                     * Start KVM monitoring 
                     */
                    fprintf(stdout,"Start KVM cvhome:%s\n", cv4home);

                    memset(cmdstr, '\0', sizeof(254));
                    /* check if the script is active, kill if found, don't need to check return code*/
                    strcpy(cmdstr, "kill -9 `ps -elf | grep cv4KVM | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    /* remove local copy, don't need to check return code */
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4KVM");
                    run_my_script (cmdstr);

                    /* decrypt KVM */ 
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4KVM.enc -out "); 
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4KVM -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt KVM file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod +x ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4KVM");
                       run_my_script(cmdstr);
                    }
                    /* start KVM monitoring */
                    sleep(1);               
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4KVM > /var/log/cv4log/kvm_mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4KVM 2>&1 &"); 
#endif
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run KVM monitoring.\n");

                    /* remove local copy, don't need to check return code */
                    sleep(2);               
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4KVM");
                    run_my_script (cmdstr);

                    fprintf(stdout, "KVM monitoring started from %s\n\n", cv4home);
                }
            } else if (strcmp(cvalue, "DOCKER") == 0 || strcmp(cvalue, "docker") == 0) {
                /* Check if core file exists */
                memset(fullpathtofile, '\0', sizeof(100));
                strcpy(fullpathtofile, cv4home);
                strcat(fullpathtofile, "/.cv4DOCKER.enc"); 
                if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                    /*
                     * Start DOCKER monitoring 
                     */
                    fprintf(stdout,"Start DOCKER cvhome:%s\n", cv4home);

                    memset(cmdstr, '\0', sizeof(254));
                    /* check if the script is active, kill if found, don't need to check return code*/
                    strcpy(cmdstr, "kill -9 `ps -elf | grep cv4DOCKER | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    /* remove local copy, don't need to check return code */
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4DOCKER");
                    run_my_script (cmdstr);

                    /* decrypt DOCKER */ 
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4DOCKER.enc -out "); 
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4DOCKER -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt DOCKER file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod +x ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4DOCKER");
                       run_my_script(cmdstr);
                    }
                    /* start DOCKER monitoring */
                    sleep(1);               
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4DOCKER > /var/log/cv4log/kvm_mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4DOCKER 2>&1 &"); 
#endif
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run DOCKER monitoring.\n");

                    /* remove local copy, don't need to check return code */
                    sleep(2);               
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4DOCKER");
                    run_my_script (cmdstr);

                    fprintf(stdout, "DOCKER monitoring started from %s\n\n", cv4home);
                }

            } else if (strcmp(cvalue, "CRES") == 0 || strcmp(cvalue, "cres") == 0) {

                /* Check if core file exists */
                memset(fullpathtofile, '\0', sizeof(100));
                strcpy(fullpathtofile, cv4home);
                strcat(fullpathtofile, "/.cv4CRES.enc"); 
                if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                    /*
                     * Start CRES monitoring 
                     */
                    memset(cmdstr, '\0', sizeof(254));
                    /* check if the script is active, kill if found, don't need to check return code*/
                    strcpy(cmdstr, "kill `ps -elf | grep cv4CRES | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    /* remove local copy, don't need to check return code */
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4CRES");
                    run_my_script (cmdstr);
                    /* decrypt CRES */ 
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4CRES.enc -out "); 
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4CRES -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt CRES file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod +x ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4CRES");
                       run_my_script(cmdstr);
                    }
                    /* start CRES monitoring */
                    sleep(1);               
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4CRES > /var/log/cv4log/CritRes.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4CRES 2>&1 &"); 
#endif
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run CRES monitoring.\n");
                    //else
                    //   fprintf(stdout, "CRES monitoring started from %s\n\n", cv4home);

                    /* remove local copy, don't need to check return code */
                    sleep(1);               
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4CRES");
                    run_my_script (cmdstr);
                } 
                else 
                {
                    fprintf(stdout, "Imcomplete installation.  Missing core application file to run Critical Resource monitoring.  Please double check path to CV4_HOME\n");
                }
            } else if (strcmp(cvalue, "PORT") == 0 || strcmp(cvalue, "port") == 0) {
                /*
                 * Start PORT monitoring 
                 */

                /* Check if core file exists */
                memset(fullpathtofile, '\0', sizeof(100));
                strcpy(fullpathtofile, cv4home);
                strcat(fullpathtofile, "/.cv4PORT.enc"); 
                if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                    /* check if the script is active, kill if found, don't need to check return code*/
                    strcpy(cmdstr, "kill `ps -elf | grep cv4PORT | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    /* remove local copy, don't need to check return code */
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4PORT");
                    run_my_script (cmdstr);
                    /* decrypt PORT */ 
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4PORT.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4PORT -pass pass:roland1");
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt PORT file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4PORT");
                       run_my_script(cmdstr);
                    }
                    /* start PORT monitoring */
                    sleep(1);               
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4PORT > /var/log/cv4log/PortMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4PORT 2>&1 &"); 
#endif
                    sleep(1);               
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run PORT monitoring.\n");
                    //else
                    //   fprintf(stdout, "PORT monitoring started from %s\n\n", cv4home);
                    /* remove local copy, don't need to check return code */
                    sleep(2);               
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4PORT");
                    run_my_script (cmdstr);
                }
                else 
                {
                    fprintf(stdout, "Imcomplete installation.  Missing core application file to run Port monitoring.  Please double check path to CV4_HOME\n");
                }
            } else if (strcmp(cvalue, "NODE") == 0 || strcmp(cvalue, "node") == 0) {
                /*
                 * Start NODES monitoring 
                 */

                /* Check if core file exists */
                memset(fullpathtofile, '\0', sizeof(100));
                strcpy(fullpathtofile, cv4home);
                strcat(fullpathtofile, "/.cv4IF.enc"); 
                if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                    /* check if the script is active, kill if found, don't need to check return code*/
                    strcpy(cmdstr, "kill `ps -elf | grep cv4IF | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
    
                    strcpy(cmdstr, "kill `ps -elf | grep cv4UDP | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);

                    strcpy(cmdstr, "kill `ps -elf | grep cv4KVM | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4DOCKER | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);

                    /* 10-14-2011 combined TCP and IPv4 into one script to fix bug#736*/
                    strcpy(cmdstr, "kill `ps -elf | grep cv4TCPIPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4IPv6 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4ICMPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4ICMPv6 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4TrapSender | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgIF | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgICMPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgTCPIPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgUDP | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
    
                    /* remove local copy, don't need to check return code */
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4*");
                    run_my_script (cmdstr);
   

                    /*r1-- decrypt DOCKER */ 
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4DOCKER.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4DOCKER -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt DOCKER file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4DOCKER");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4DOCKER > /var/log/cv4log/DockerMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4DOCKER 2>&1 &"); 
#endif
                    /* start DOCKER monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run DOCKER monitoring.\n");
                    //else
                    //   fprintf(stdout, "Docker monitoring started from %s\n\n", cv4home);
 
                    /*r1-- decrypt IF */ 
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4IF.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4IF -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt IF file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4IF");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4IF > /var/log/cv4log/InterfaceMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4IF 2>&1 &"); 
#endif
                    /* start IF monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run IF monitoring.\n");
                    //else
                    //   fprintf(stdout, "Interface monitoring started from %s\n\n", cv4home);
    
                    /*r2-- decrypt TCPIPv4-ProcessView */
                    sleep(2);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                        strcat(cmdstr, "/.cv4TCPIPv4.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4TCPIPv4 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt TCPIPv4 file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4TCPIPv4");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG
                    strcat(cmdstr, "/tmp/.cv4TCPIPv4 > /var/log/cv4log/ProcessMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4TCPIPv4 2>&1 &"); 
#endif
                    /* start TCPIPv4-ProcessView monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run TCPIPv4-ProcessView monitoring.\n");
                    //else
                    //   fprintf(stdout, "ProcessView monitoring started from %s\n\n", cv4home);
    
                    /*r3-- decrypt ICMPv4 */ 
                    sleep(2);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4ICMPv4.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4ICMPv4 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt ICMPv4 file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4ICMPv4");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4ICMPv4 > /var/log/cv4log/ICMPv4Mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4ICMPv4 2>&1 &"); 
#endif
                    /* start ICMPv4 monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run ICMPv4 monitoring.\n");
                    //else
                    //   fprintf(stdout, "ICMPv4 monitoring started from %s\n\n", cv4home);
    
                    /*r4-- decrypt ICMPv6 */ 
                    sleep(2);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4ICMPv6.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4ICMPv6 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt ICMPv6 file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4ICMPv6");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4ICMPv6 > /var/log/cv4log/ICMPv6Mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4ICMPv6 2>&1 &"); 
#endif
                    /* start ICMPv6 monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run ICMPv6 monitoring.\n");
                    //else
                    //   fprintf(stdout, "ICMPv6 monitoring started from %s \n\n", cv4home);
              
                    /*r6-- decrypt IPv6 */ 
                    sleep(1);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4IPv6.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4IPv6 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt IPv6 file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4IPv6");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4IPv6 > /var/log/cv4log/IPv6Mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4IPv6 2>&1 &"); 
#endif
                    /* start IPv6 monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run IPv6 monitoring.\n");
                    //else
                    //   fprintf(stdout, "IPv6 monitoring started from %s\n\n", cv4home);
    
                    /*r8-- decrypt UDP */ 
                    sleep(2);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4UDP.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4UDP -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt UDP file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4UDP");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4UDP > /var/log/cv4log/UDPMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4UDP 2>&1 &"); 
#endif
                    /* start UDP monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run UDP monitoring.\n");
                    //else
                    //   fprintf(stdout, "UDP monitoring started from %s\n", cv4home);
    
                    /*r9-- decrypt TrapSender */ 
                    sleep(2);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4TrapSender.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4TrapSender -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt cv4TrapSender file.\n");
                    else
                    {
                       strcpy(cmdstr, "chmod 555 ");
                       strcat(cmdstr, cv4home);
                       strcat(cmdstr, "/tmp/.cv4TrapSender");
                       run_my_script(cmdstr);
                    }
                    strcpy(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4TrapSender > /var/log/cv4log/TrapMsgMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4TrapSender 2>&1 &"); 
#endif
                    /* start TrapSender monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run TrapSender.\n");
                    //else
                    //   fprintf(stdout, "Trap messaging started from %s\n", cv4home);
    
    
                    /* remove local copy, don't need to check return code */
                    sleep(2);               
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4*");
                    run_my_script (cmdstr);
                }
                free(cmdstr);
            } 
            else 
            {
                fprintf(stdout, "Imcomplete installation.  Missing core application file to run node monitoring.  Please double check path to CV4_HOME\n");
            }
        }
        break;
     case 'e': /* -e == end script */
               /* expect syntax: cv4monwrapper -e {cres|port|node} */
        eflag = 1;
        cvalue = optarg;
        if (argc > 1) {
            if (strcmp(cvalue, "KVM") == 0 || strcmp(cvalue, "kvm") == 0) {
                /*
                * Stop CRES monitoring 
                */
                memset(cmdstr, '\0', sizeof(254));
                /* check if the script is active, kill if found, don't need to check return code*/
                strcpy(cmdstr, "kill -9 `ps -elf | grep .cv4KVM | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);

            } else if (strcmp(cvalue, "DOCKER") == 0 || strcmp(cvalue, "docker") == 0) {
                /*
                * Stop CRES monitoring 
                */
                memset(cmdstr, '\0', sizeof(254));
                /* check if the script is active, kill if found, don't need to check return code*/
                strcpy(cmdstr, "kill -9 `ps -elf | grep .cv4DOCKER | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);

            } else if (strcmp(cvalue, "CRES") == 0 || strcmp(cvalue, "cres") == 0) {
                /*
                * Stop CRES monitoring 
                */
                memset(cmdstr, '\0', sizeof(254));
                /* check if the script is active, kill if found, don't need to check return code*/
                strcpy(cmdstr, "kill `ps -elf | grep .cv4CRES | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                /* remove local copy, don't need to check return code */
                //strcpy(cmdstr, "rm -f ");
                //strcat(cmdstr, cv4home);
                //strcat(cmdstr, "/tmp/.cv4CRES");
                //run_my_script (cmdstr);

                //fprintf( stdout, "Critical resources monitoring stopped.\n");
            } else if (strcmp(cvalue, "PORT") == 0 || strcmp(cvalue, "port") == 0) {
                /*
                 * Stop PORT monitoring 
                 */
                memset(cmdstr, '\0', sizeof(254));
                /* check if the script is active, kill if found, don't need to check return code*/
                strcpy(cmdstr, "kill `ps -elf | grep .cv4PORT | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                /* remove local copy, don't need to check return code */
                //strcpy(cmdstr, "rm -f ");
                //strcat(cmdstr, cv4home);
                //strcat(cmdstr, "/tmp/.cv4PORT");
                //run_my_script (cmdstr);

                //fprintf( stdout, "PortMon monitoring stopped.\n");
            } else if (strcmp(cvalue, "NODE") == 0 || strcmp(cvalue, "node") == 0) {
                /*
                 * Stop NODES monitoring 
                 */
                memset(cmdstr, '\0', sizeof(254));
                /* check if the script is active, kill if found, don't need to check return code*/
                strcpy(cmdstr, "kill `ps -elf | grep .cv4IF | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                strcpy(cmdstr, "kill `ps -elf | grep bgIF | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                strcpy(cmdstr, "kill `ps -elf | grep bgICMPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                strcpy(cmdstr, "kill `ps -elf | grep bgTCPIPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                strcpy(cmdstr, "kill `ps -elf | grep bgUDP | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);

                strcpy(cmdstr, "kill `ps -elf | grep .cv4UDP | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                strcpy(cmdstr, "kill `ps -elf | grep .cv4UDP | grep .1.3.6.1.2.1.7.1.0 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);

                strcpy(cmdstr, "kill `ps -elf | grep .cv4TCPIPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                strcpy(cmdstr, "kill `ps -elf | grep .cv4TCPIPv4 | grep .1.3.6.1.2.1.6.5.0 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);

                strcpy(cmdstr, "kill `ps -elf | grep .cv4IPv6 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                //strcpy(cmdstr, "kill `ps -elf | grep .cv4IPv6 | grep .1.3.6.1.2.1.6.5.0 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                //run_my_script (cmdstr);

                strcpy(cmdstr, "kill `ps -elf | grep .cv4ICMPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);
                strcpy(cmdstr, "kill `ps -elf | grep .cv4TCPIPv4 | grep .1.3.6.1.2.1.5.1.0 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);

                strcpy(cmdstr, "kill `ps -elf | grep .cv4ICMPv6 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                run_my_script (cmdstr);

                /* remove local copy, don't need to check return code */
                strcpy(cmdstr, "rm -f ");
                strcat(cmdstr, cv4home);
                strcat(cmdstr, "/tmp/.cv4*");
                run_my_script (cmdstr);
                //fprintf( stdout, "Nodes monitoring stopped.\n");
            }
            free(cmdstr);
        }
        break;
     case 'r': /* -r == restart script */
               /* expect syntax: cv4monwrapper -r {cres|port|node} */
        rflag = 1;
        cvalue = optarg;
        if (argc > 1) {
           if (strcmp(cvalue, "KVM") == 0 || strcmp(cvalue, "kvm") == 0) {
                /*
                * Start KVM monitoring 
                */
               fprintf(stdout,"Start KVM cvhome:%s\n", cv4home);

               memset(cmdstr, '\0', sizeof(254));
               /* check if the script is active, kill if found, don't need to check return code*/
               strcpy(cmdstr, "kill -9 `ps -elf | grep cv4KVM | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
               run_my_script (cmdstr);
               /* remove local copy, don't need to check return code */
               strcpy(cmdstr, "rm -f ");
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/tmp/.cv4KVM");
               run_my_script (cmdstr);

               /* decrypt KVM */ 
               strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/.cv4KVM.enc -out "); 
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/tmp/.cv4KVM -pass pass:roland1"); 
               if (run_my_script (cmdstr) == -1)
                  fprintf(stderr, "Failed to decrypt KVM file.\n");
               else
               {
                  strcpy(cmdstr, "chmod +x ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4KVM");
                  run_my_script(cmdstr);
               }
               /* start KVM monitoring */
               sleep(1);               
               strcpy(cmdstr, cv4home);
#ifdef LOG 
               strcat(cmdstr, "/tmp/.cv4KVM > /var/log/cv4log/kvm_mon.log 2>&1 &"); 
#else
               strcat(cmdstr, "/tmp/.cv4KVM 2>&1 &"); 
#endif
               if (run_my_script (cmdstr) == -1)
                  fprintf(stderr, "Failed to run KVM monitoring.\n");

               /* remove local copy, don't need to check return code */
               sleep(2);               
               strcpy(cmdstr, "rm -f ");
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/tmp/.cv4KVM");
               run_my_script (cmdstr);

               fprintf(stdout, "KVM monitoring started from %s\n\n", cv4home);

           } else if (strcmp(cvalue, "DOCKER") == 0 || strcmp(cvalue, "docker") == 0) {
                /*
                * Start Docker monitoring 
                */
               fprintf(stdout,"Start Docker cvhome:%s\n", cv4home);

               memset(cmdstr, '\0', sizeof(254));
               /* check if the script is active, kill if found, don't need to check return code*/
               strcpy(cmdstr, "kill -9 `ps -elf | grep cv4DOCKER | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
               run_my_script (cmdstr);
               /* remove local copy, don't need to check return code */
               strcpy(cmdstr, "rm -f ");
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/tmp/.cv4DOCKER");
               run_my_script (cmdstr);

               /* decrypt DOCKER */ 
               strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/.cv4DOCKER.enc -out "); 
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/tmp/.cv4DOCKER -pass pass:roland1"); 
               if (run_my_script (cmdstr) == -1)
                  fprintf(stderr, "Failed to decrypt DOCKER file.\n");
               else
               {
                  strcpy(cmdstr, "chmod +x ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4DOCKER");
                  run_my_script(cmdstr);
               }
               /* start DOCKER monitoring */
               sleep(1);               
               strcpy(cmdstr, cv4home);
#ifdef LOG 
               strcat(cmdstr, "/tmp/.cv4DOCKER > /var/log/cv4log/DockerMon.log 2>&1 &"); 
#else
               strcat(cmdstr, "/tmp/.cv4DOCKER 2>&1 &"); 
#endif
               if (run_my_script (cmdstr) == -1)
                  fprintf(stderr, "Failed to run Docker monitoring.\n");

               /* remove local copy, don't need to check return code */
               sleep(2);               
               strcpy(cmdstr, "rm -f ");
               strcat(cmdstr, cv4home);
               strcat(cmdstr, "/tmp/.cv4DOCKER");
               run_my_script (cmdstr);

           } else if (strcmp(cvalue, "CRES") == 0 || strcmp(cvalue, "cres") == 0) {
               /* Check if core file exists */
               memset(fullpathtofile, '\0', sizeof(100));
               strcpy(fullpathtofile, cv4home);
               strcat(fullpathtofile, "/.cv4CRES.enc"); 
               if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                  /*
                  * Restart CRES monitoring 
                  */
                  memset(cmdstr, '\0', sizeof(254));
                  /* check if the script is active, kill if found, don't need to check return code*/
                  strcpy(cmdstr, "kill `ps -elf | grep .cv4CRES | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                  run_my_script (cmdstr);
                  /* remove local copy, don't need to check return code */
                  strcpy(cmdstr, "rm -f ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4CRES");
                  run_my_script (cmdstr);
                  /* decrypt CRES */ 
                  strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/.cv4CRES.enc -out ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4CRES -pass pass:roland1"); 
                  if (run_my_script (cmdstr) == -1)
                     fprintf(stderr, "Failed to decrypt CRES file.\n");
                  /* start CRES monitoring */
                  strcpy(cmdstr, "sh ");
                  strcat(cmdstr, cv4home);
#ifdef LOG 
                  strcat(cmdstr, "/tmp/.cv4CRES > /var/log/cv4log/CritRes.log 2>&1 &"); 
#else
                  strcat(cmdstr, "/tmp/.cv4CRES 2>&1 &"); 
#endif
                  if (run_my_script (cmdstr) == -1)
                     fprintf(stderr, "Failed to run CRES monitoring.\n");
                  //else
                  //   fprintf(stdout, "CRES monitoring restarted from %s\n\n", cv4home);
                  /* remove local copy, don't need to check return code */
                  sleep(1);               
                  strcpy(cmdstr, "rm -f ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4CRES");
                  run_my_script (cmdstr);
                  free(cmdstr);
               } else {
                  fprintf(stdout, "Incomplete installation.  Missing core file to run Critical Resource monitoring.  Please double check path to CV4_HOME\n");
               }
            } else if (strcmp(cvalue, "PORT") == 0 || strcmp(cvalue, "port") == 0) {
               /* Check if core file exists */
               memset(fullpathtofile, '\0', sizeof(100));
               strcpy(fullpathtofile, cv4home);
               strcat(fullpathtofile, "/.cv4PORT.enc"); 
               if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                  /*
                   * Restart PORT monitoring 
                   */
                  memset(cmdstr, '\0', sizeof(254));
                  /* check if the script is active, kill if found, don't need to check return code*/
                  strcpy(cmdstr, "kill `ps -elf | grep .cv4PORT | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                  run_my_script (cmdstr);
                  /* remove local copy, don't need to check return code */
                  strcpy(cmdstr, "rm -f ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4PORT");
                  run_my_script (cmdstr);
                  /* decrypt PORT */ 
                  strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/.cv4PORT.enc -out ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4PORT -pass pass:roland1");
                  if (run_my_script (cmdstr) == -1)
                     fprintf(stderr, "Failed to decrypt PORT file.\n");
                  /* start PORT monitoring */
                  sleep(1);               
                  strcpy(cmdstr, "sh ");
                  strcat(cmdstr, cv4home);
#ifdef LOG 
                  strcat(cmdstr, "/tmp/.cv4PORT > /var/log/cv4log/PortMon.log 2>&1 &"); 
#else
                  strcat(cmdstr, "/tmp/.cv4PORT 2>&1 &"); 
#endif
                  if (run_my_script (cmdstr) == -1)
                     fprintf(stderr, "Failed to run PORT monitoring.\n");
                  //else
                  //   fprintf(stdout, "PORT monitoring started from %s\n\n", cv4home);
                  /* remove local copy, don't need to check return code */
                  sleep(1);               
                  strcpy(cmdstr, "rm -f ");
                  strcat(cmdstr, cv4home);
                  strcat(cmdstr, "/tmp/.cv4PORT");
                  run_my_script (cmdstr);

                  free(cmdstr);
                } else {
                  fprintf(stdout, "Imcomplete installation.  Missing core file to run Port monitoring.  Please double check path to CV4_HOME\n");
                }
            } else if (strcmp(cvalue, "NODE") == 0 || strcmp(cvalue, "node") == 0) {
                /* Check if core file exists */
                memset(fullpathtofile, '\0', sizeof(100));
                strcpy(fullpathtofile, cv4home);
                strcat(fullpathtofile, "/.cv4IF.enc"); 
                if ((fp=fopen(fullpathtofile, "r")) != NULL) {
                    /*
                     * Restart NODES monitoring 
                     */
                    memset(cmdstr, '\0', sizeof(254));
                    /* check if the script is active, kill if found, don't need to check return code*/
                    strcpy(cmdstr, "kill `ps -elf | grep cv4IF | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4UDP | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4TCPIPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4IPv6 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4ICMPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4ICMPv6 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep cv4TrapSender | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgIF | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgICMPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgTCPIPv4 | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
                    strcpy(cmdstr, "kill `ps -elf | grep bgUDP | grep -v grep | cut -c 12-19` > /dev/null  2>&1");
                    run_my_script (cmdstr);
    
                    /* remove local copy, don't need to check return code */
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4*");
                    run_my_script (cmdstr);
    
                    /*r1-- decrypt IF */ 
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4IF.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4IF -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt IF file.\n");
                    strcpy(cmdstr, "sh ");
                    strcat(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4IF > /var/log/cv4log/InterfaceMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4IF 2>&1 &"); 
#endif
                    /* start IF monitoring */
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run IF monitoring.\n");
                    //else
                    //   fprintf(stdout, "Interface monitoring restarted from %s\n\n", cv4home);
    
                    /*r2-- decrypt TCPIPv4-ProcessView */ 
                    sleep(1);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4TCPIPv4.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4TCPIPv4 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt TCPIP-ProcessView file.\n");
                    strcpy(cmdstr, "sh ");
                    strcat(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4TCPIPv4 > /var/log/cv4log/ProcessMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4TCPIPv4 2>&1 &"); 
#endif
                    /* start PR monitoring */
                    sleep(1);               
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run TCPIP-ProcessView monitoring.\n");
                    //else
                    //   fprintf(stdout, "ProcessView monitoring restarted from %s\n\n", cv4home);
    
                    /*r3-- decrypt ICMPv4 */ 
                    sleep(1);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4ICMPv4.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4ICMPv4 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt ICMPv4 file.\n");
                    strcpy(cmdstr, "sh ");
                    strcat(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4ICMPv4 > /var/log/cv4log/ICMPv4Mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4ICMPv4 2>&1 &"); 
#endif
                    /* start ICMPv4 monitoring */
                    sleep(1);               
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run ICMPv4 monitoring.\n");
                    //else
                    //   fprintf(stdout, "ICMPv4 monitoring restarted from %s\n\n", cv4home);
    
                    /*r4-- decrypt ICMPv6 */ 
                    sleep(1);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4ICMPv6.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4ICMPv6 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt ICMPv6 file.\n");
                    strcpy(cmdstr, "sh ");
                    strcat(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4ICMPv6 > /var/log/cv4log/ICMPv6Mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4ICMPv6 2>&1 &"); 
#endif
                    /* start ICMPv6 monitoring */
                    sleep(1);               
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run ICMPv6 monitoring.\n");
                    //else
                    //   fprintf(stdout, "ICMPv6 monitoring restarted from %s\n\n", cv4home);
              
    
                    /*r6-- decrypt IPv6 */ 
                    sleep(1);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4IPv6.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4IPv6 -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt IPv6 file.\n");
                    strcpy(cmdstr, "sh ");
                    strcat(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4IPv6 > /var/log/cv4log/IPv6Mon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4IPv6 2>&1 &"); 
#endif
                    /* start IPv6 monitoring */
                    sleep(1);               
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run IPv6 monitoring.\n");
                    //else
                    //   fprintf(stdout, "IPv6 monitoring restarted from %s\n\n", cv4home);
    
              
                    /*r8-- decrypt UDP */ 
                    sleep(1);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4UDP.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4UDP -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt UDP file.\n");
                    strcpy(cmdstr, "sh ");
                    strcat(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4UDP > /var/log/cv4log/UDPMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4UDP 2>&1 &"); 
#endif
                    /* start UDP monitoring */
                    sleep(2);               
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run UDP monitoring.\n");
                    //else
                    //   fprintf(stdout, "UDP monitoring restarted from %s\n", cv4home);
              
                    /*r9-- decrypt TrapSender */ 
                    sleep(1);               
                    strcpy(cmdstr, "openssl enc -d -aes-128-ecb -salt -in ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/.cv4TrapSender.enc -out ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4TrapSender -pass pass:roland1"); 
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to decrypt TrapSender file.\n");
                    strcpy(cmdstr, "sh ");
                    strcat(cmdstr, cv4home);
#ifdef LOG 
                    strcat(cmdstr, "/tmp/.cv4TrapSender > /var/log/cv4log/TrapMsgMon.log 2>&1 &"); 
#else
                    strcat(cmdstr, "/tmp/.cv4TrapSender 2>&1 &"); 
#endif
                    /* start TrapSender monitoring */
                    sleep(2);               
                    if (run_my_script (cmdstr) == -1)
                       fprintf(stderr, "Failed to run TrapSender messaging.\n");
    
    
                    /* remove local copy, don't need to check return code */
                    sleep(2);               
                    strcpy(cmdstr, "rm -f ");
                    strcat(cmdstr, cv4home);
                    strcat(cmdstr, "/tmp/.cv4*");
                    run_my_script (cmdstr);
                    free(cmdstr);
                } else {
                    fprintf(stdout, "Incomplete installation.  Missing core file to run node monitoring.  Please double check path to CV4_HOME\n");
                }
            }
        }
        break;
     case '?':
        if (optopt == 's' || optopt == 'e' || optopt == 'r')
           fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
           fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
           fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
        return 1;
     default:
        fprintf(stdout, "Usage: $1 -ser {[cres, port, node, kvm]}\n");
        abort ();
  }
  /*   
  printf ("sflag = %d, eflag = %d, rflag = %d, cvalue = %s\n", sflag, eflag, rflag, cvalue);
  for (index = optind; index < argc; index++)
     printf ("Non-option argument index:%d value:%s\n", index, argv[index]);
  */
  return 0;
}



