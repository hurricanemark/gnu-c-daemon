#include "commands.h"


/*-------------------------------------------------------------------*/
/* returns local IP address associate with eth0                      */
/*-------------------------------------------------------------------*/
char* getIP(const char* interface)
{
   int iSocket = -1;
   char* IP = 0;
    
   // create a socket to be used when calling ioctl().
   if ((iSocket = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
   {
      perror("socket");
      return 0;
   }

   // if_nameindex - return all network interface names and indexes    
   struct if_nameindex* pIndex  = if_nameindex();
   struct if_nameindex* pIndex2 = pIndex;

   while ((pIndex != NULL) && (pIndex->if_name != NULL))
   {
      struct ifreq req;

      strncpy(req.ifr_name, pIndex->if_name, IFNAMSIZ);

      // ioctl - control a STREAMS device
      if (ioctl(iSocket, SIOCGIFADDR, &req) < 0)
      {
         if (errno == EADDRNOTAVAIL)
         {
            ++pIndex;
            continue;
         }
         perror("ioctl");
         close(iSocket);
         return 0;
      }

      if (strncmp(interface, pIndex->if_name, strlen(interface)) == 0)
      {
         IP = strdup(inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr));
         break;
      }
      ++pIndex;
   }


   // if_freenameindex - free memory allocated by if_nameindex
   if_freenameindex(pIndex2);

   close(iSocket);

   return IP;
}

/*-------------------------------------------------------------------*/
/* get community name from a specified node                          */ 
/*-------------------------------------------------------------------*/
char *getCommunityName(char *SVERIP, char *NODEIP)
{
   MYSQL *conn;
   MYSQL_RES *res;
   MYSQL_ROW row;
   unsigned int num_cols=0;
   char *server = "137.72.43.204";
   char *user = "clevermonitor";
   char *password = "cleverview7070"; /* set me first */
   char *database = "CV4LINUXMASTER";
   unsigned char *sqlstmt = malloc(250 * sizeof(unsigned char));
   int x;
   //char CommunStr[50];
   //char *CommunStr;
   //CommunStr = (char *) malloc(sizeof(140));
   char* CommunStr = malloc(CNAMESIZE * sizeof(char));

   printf("DEBUG-- Start getCommunityName with servrip:%s nodeip: %s\n", SVERIP, NODEIP);
   //sqlstmt = (char *) malloc(sizeof(200));
   strcpy(sqlstmt, "SELECT DECODE(NodeCommunityName, 'ernrdhtclm') FROM node_conf WHERE NodeIPAddr='");
   strcat(sqlstmt, NODEIP);
   strcat(sqlstmt, "';");

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
   fprintf(stdout, "DEBUG: CommunityName=%s\n", CommunStr);

   /* close connection */
   mysql_free_result(res);
   mysql_close(conn);
   return CommunStr;
}


/*-------------------------------------------------------------------*/
/* Connect, and execute an SQL statement then disconnect             */ 
/*-------------------------------------------------------------------*/
int mySQLexec(mySqlCmd_t *MYSQLCMD)
{

   char *user = "clevermonitor";
   char *password = "cleverview7070"; /* set me first */
   char *database = "CV4LINUXMASTER";

   MYSQL *conn;
   //MYSQL_RES *res;

   /*-- show local ip address --*/
   //printf("DEBUG3--\nLocalIP:%s SQLSTMT: %s\n", MYSQLCMD->monitorip, MYSQLCMD->sqlcmdstmt);

   conn = mysql_init(NULL);
   //fprintf(stdout, "DEBUG-- Connecting to MySQL server %s\n", MYSQLCMD->monitorip);

   /* Connect to database */
   if (!mysql_real_connect(conn, MYSQLCMD->monitorip,
         user, password, database, 0, NULL, 0)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
      return 1;
   }

   /* send an SQL query */
   if (mysql_query(conn, MYSQLCMD->sqlcmdstmt)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
      return 1;
   }

   //res = mysql_use_result(conn);

   /* close connection */
   //mysql_free_result(res);
   mysql_close(conn);

   return 0;
}
