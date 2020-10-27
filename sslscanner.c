#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <process.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


CRITICAL_SECTION CSip;
CRITICAL_SECTION pantalla;
CRITICAL_SECTION CSThreads;
int ip1[4],ip2[4];
int MAX_THREADS=100;
int CONN_TIMEOUT=8;
int ThreadsActivos=0;
HANDLE *hThread;
#define request "HEAD / HTTP/1.0\r\n\r\n"


char *conecta(char *target);
/******************************************************************************/
char *GetNextTarget(char *ip) {

        EnterCriticalSection(&CSip);

	if (ip1[3]!=254)
                ip1[3]++;
	else {
		ip1[2]++;
		ip1[3]=1;
	}
	if (ip1[2]==255) {
                ip1[2]++; ip1[1]++;
        }
        LeaveCriticalSection(&CSip);

	if (ip1[2]>ip2[2])   return(NULL);
	if (ip1[2]==ip2[2])
		if (ip1[3]>ip2[3]) return(NULL);

	sprintf(ip,"%d.%d.%d.%d",ip1[0],ip1[1],ip1[2],ip1[3]);
	return(ip);
}

/******************************************************************************/
void Escanea( void *thread) {

char ip[16];
char *p;
int i=thread;
char *banner;
char *r;

EnterCriticalSection(&CSThreads);
ThreadsActivos++;
LeaveCriticalSection(&CSThreads);
memset(ip,'\0',sizeof(ip));

while (GetNextTarget(ip)!=NULL) {
        p=conecta(ip);
        if (p!=NULL) {
                EnterCriticalSection(&pantalla);
                banner=strstr(p,"\r\nServer: ");
                if (!banner) {
                        banner=strstr(p,"UNKNOWN: HTTP/1.1");
                         if (!banner)
                                printf(" -Server %s   \tONLINE (HTTP/1.1)\n",ip);
                        else
                        printf(" -Server %s   \tONLINE (UNKNOWN: %s)\n",ip,p);
                } else {
                        r=strchr(banner+2,'\r');
                        if (r) r[0]='\0';
                        printf(" -Server %s   \tONLINE (%s)\n",ip,banner+strlen("\r\nServer: "));
                }
                LeaveCriticalSection(&pantalla);
                free(p);
        } else {
                EnterCriticalSection(&pantalla);
                //printf(" - [%i] Server %s OFFLINE\n",i,ip);
                LeaveCriticalSection(&pantalla);
        }

}
EnterCriticalSection(&CSThreads);
ThreadsActivos--;
LeaveCriticalSection(&CSThreads);
printf(".");
_endthread();


}
/******************************************************************************/
char *conecta(char *target) {
        int sock;
        struct sockaddr_in haxorcitos;
        struct sockaddr_in servaddr;
        char *resultado=NULL;
        char buf[1000];
        SSL_CTX *ctx;
        SSL *ssl;
        int err;
        int total=0;
        int read_size;


        struct timeval tv;
        u_long tmp=1;
        fd_set fds;
        int i;

        sock=socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
        haxorcitos.sin_family = AF_INET;
        haxorcitos.sin_addr.s_addr = inet_addr(target);
        haxorcitos.sin_port = htons(443);
        tmp=1;
        ioctlsocket( sock, FIONBIO, &tmp);
        tv.tv_sec = CONN_TIMEOUT;
        tv.tv_usec = 0;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        connect(sock,( struct sockaddr *)&haxorcitos,sizeof(haxorcitos));

        if(!(i=select(sock+1,0,&fds,0,&tv))>0) {
                closesocket(sock);
                return(NULL);
        }


        tmp=0;
        ioctlsocket( sock, FIONBIO, &tmp); //TODO: Controlar Errores de SSL y timeouts.
        SSL_load_error_strings();
        SSL_library_init();
        ctx=SSL_CTX_new(SSLv2_client_method());
        ssl=SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        err=SSL_connect(ssl);
        err=SSL_write(ssl, request, strlen(request));

while(1) {
       read_size=SSL_read(ssl, buf, sizeof(buf)-1);
        if(read_size > 0)  {
        buf[read_size]='\0';
        total=total+read_size;
                if (resultado==NULL) {
                        resultado=(char *)malloc(total+1);
                        memcpy(resultado,buf,read_size);
                } else {
                        resultado=(char *)realloc(resultado,total+1);
                        memcpy(resultado+(total-read_size),buf,read_size);
                }
                resultado[total]='\0';
        } else {
                break;
        }
}

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);


closesocket(sock);
return(resultado);

}

/******************************************************************************/
void usage(void) {
	printf(" USAGE:   Httpss.exe ip1 ip2 [THREADS] [TIMEOUT]\n");
	printf(" Example: Https.exe 192.168.0.34 192.168.20.255 200 6\n");
        exit(1);
}
/******************************************************************************/



int main(int argc, char* argv[]){
WSADATA ws;
int i,j,totalips;
int salir=0;
int params[4];
FILE *EHTTPS;
char celda[256];
char linea[80];

printf("\n . .. ...: HTTPS Scanner v1.0 (aT4r@haxorcitos.com) :... ...\n\n");

if (!((argc==3) || (argc==5)))
	usage();
if (argc==5) {
	MAX_THREADS=atoi(argv[3]);
	CONN_TIMEOUT=atoi(argv[4]);
}
 if (WSAStartup( MAKEWORD(2,2), &ws )!=0) {
        printf(" [+] WSAStartup() error\n");
	exit(0);
 }

 sscanf (argv[1], "%d.%d.%d.%d", &ip1[0],&ip1[1],&ip1[2],&ip1[3]);
 sscanf (argv[2], "%d.%d.%d.%d", &ip2[0],&ip2[1],&ip2[2],&ip2[3]);

 for(i=0;i<4;i++){
	if ( (ip1[i]>255) || (ip1[i]<0) ) usage();
	if ( (ip2[i]>255) || (ip2[i]<0) ) usage();

 }
 if ((ip2[0]!=ip1[0]) || (ip2[1]!=ip1[1])){
 	printf("\n error. MAX HOSTS = %i\n",(int)(255*255));
	exit(0);
 }

InitializeCriticalSection(&CSip);
InitializeCriticalSection(&pantalla);
InitializeCriticalSection(&CSThreads);
 for(i=0;i<MAX_THREADS;i++) {
        _beginthread(Escanea,4096,(void *)i);
 }

 Sleep(100);  while(ThreadsActivos>0) {   Sleep(500);  }
 printf("scan Finished\n");
 return(1);
}
//---------------------------------------------------------------------------
