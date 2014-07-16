#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <windows.h>
#include <string>
#include <iostream>
#include <string>
#include <iostream>
#include <stdio.h>
#include <set>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 1024*2

#define TWITCH_CHANNEL_NAME "yolo"

struct in_addr TwitchTokenIPAddr;
struct in_addr TwitchUsherIPAddr;

#if 0
#define DEBUG_IP_printf printf
#define DEBUG_TOKEN_printf printf
#define DEBUG_URL_printf printf
#define DEBUG_TS_printf printf
#define DEBUG_TSList_printf printf
#define DEBUG_Main_printf printf
#else
#define DEBUG_IP_printf DummyPrintf
#define DEBUG_TOKEN_printf DummyPrintf
#define DEBUG_URL_printf DummyPrintf
#define DEBUG_TS_printf DummyPrintf
#define DEBUG_TSList_printf printf
#define DEBUG_Main_printf DummyPrintf
#endif

void DummyPrintf(...)
{
}

int GlobalPrintCounter = 0;

ptrdiff_t urldecode(char* dst, const char* src, int normalize)
{
    char* org_dst = dst;
    int slash_dot_dot = 0;
    char ch, a, b;
    do {
        ch = *src++;
        if (ch == '%' && isxdigit(a = src[0]) && isxdigit(b = src[1])) {
            if (a < 'A') a -= '0';
            else if(a < 'a') a -= 'A' - 10;
            else a -= 'a' - 10;
            if (b < 'A') b -= '0';
            else if(b < 'a') b -= 'A' - 10;
            else b -= 'a' - 10;
            ch = 16 * a + b;
            src += 2;
        }
        if (normalize) {
            switch (ch) {
            case '/':
                if (slash_dot_dot < 3) {
                    /* compress consecutive slashes and remove slash-dot */
                    dst -= slash_dot_dot;
                    slash_dot_dot = 1;
                    break;
                }
                /* fall-through */
            case '?':
                /* at start of query, stop normalizing */
                if (ch == '?')
                    normalize = 0;
                /* fall-through */
            case '\0':
                if (slash_dot_dot > 1) {
                    /* remove trailing slash-dot-(dot) */
                    dst -= slash_dot_dot;
                    /* remove parent directory if it was two dots */
                    if (slash_dot_dot == 3)
                        while (dst > org_dst && *--dst != '/')
                            /* empty body */;
                    slash_dot_dot = (ch == '/') ? 1 : 0;
                    /* keep the root slash if any */
                    if (!slash_dot_dot && dst == org_dst && *dst == '/')
                        ++dst;
                }
                break;
            case '.':
                if (slash_dot_dot == 1 || slash_dot_dot == 2) {
                    ++slash_dot_dot;
                    break;
                }
                /* fall-through */
            default:
                slash_dot_dot = 0;
            }
        }
        *dst++ = ch;
    } while(ch);
    return (dst - org_dst) - 1;
}

/* Converts a hex character to its integer value */
char from_hex(char ch) 
{
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'A' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) 
{
  static char hex[] = "0123456789ABCDEF";
  return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str, bool SkipSlashes) 
{
  char *pstr = str, *buf = (char*)malloc(strlen(str) * 3 + 1), *pbuf = buf;
  while (*pstr) 
  {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
      *pbuf++ = *pstr;
    else if (*pstr == ' ') 
      *pbuf++ = '+';
	else if( SkipSlashes == true && *pstr == '\\' )
	{
	}
    else 
      *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

static unsigned long crc32_tab[] = {
	  0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
	  0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
	  0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
	  0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
	  0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
	  0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
	  0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
	  0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
	  0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
	  0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
	  0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
	  0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
	  0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
	  0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
	  0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
	  0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
	  0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
	  0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
	  0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
	  0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
	  0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
	  0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
	  0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
	  0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
	  0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
	  0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
	  0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
	  0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
	  0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
	  0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
	  0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
	  0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
	  0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
	  0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
	  0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
	  0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
	  0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
	  0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
	  0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
	  0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
	  0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
	  0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
	  0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
	  0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
	  0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
	  0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
	  0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
	  0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
	  0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
	  0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
	  0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
	  0x2d02ef8dL
   };

/* Return a 32-bit CRC of the contents of the buffer. */

unsigned long crc32(const unsigned char *s, unsigned int len)
{
  unsigned int i;
  unsigned long crc32val;
  
  crc32val = 0;
  for (i = 0;  i < len;  i ++)
	{
	  crc32val =
	crc32_tab[(crc32val ^ s[i]) & 0xff] ^
	  (crc32val >> 8);
	}
  return crc32val;
}

int GetTwitchIPs( char *RemoteHostName, struct in_addr *AddrStore )
{
	DWORD dwError;
    struct hostent *remoteHost;

	remoteHost = gethostbyname( RemoteHostName );
    if (remoteHost == NULL)
	{
        dwError = WSAGetLastError();
        if (dwError != 0)
		{
            if (dwError == WSAHOST_NOT_FOUND)
			{
                DEBUG_IP_printf("Host not found\n");
                return 1;
            } 
			else if (dwError == WSANO_DATA) 
			{
                DEBUG_IP_printf("No data record found for %s\n", RemoteHostName );
                return 1;
            } 
			else 
			{
                DEBUG_IP_printf("Function failed with error: %ld\n", dwError);
                return 1;
            }
        }
    } 
	else 
	{
	    if( remoteHost != NULL && remoteHost->h_addrtype == AF_INET )
		{
	        AddrStore->s_addr = *(u_long *) remoteHost->h_addr_list[ 0 ];
			DEBUG_IP_printf("IP : %d.%d.%d.%d\n",AddrStore->S_un.S_un_b.s_b1,AddrStore->S_un.S_un_b.s_b2,AddrStore->S_un.S_un_b.s_b3,AddrStore->S_un.S_un_b.s_b4);
		}
    }

	return 0;
}

int GetTwitchToken( char *Token, char *Sig )
{
    //----------------------
    // Declare and initialize variables.
    int iResult;

    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService; 

//    char *sendbuf = "this is a test";
    char buffer[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
  
    //----------------------
    // Create a SOCKET for connecting to server
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) 
	{
        DEBUG_TOKEN_printf("Error at socket(): %ld\n", WSAGetLastError() );
        WSACleanup();
        return 1;
    }

 
    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port of the server to be connected to.
    clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = TwitchTokenIPAddr.s_addr;
    clientService.sin_port = htons( 80 );

    //----------------------
    // Connect to server.
    iResult = connect( ConnectSocket, (SOCKADDR*) &clientService, sizeof(clientService) );
    if ( iResult == SOCKET_ERROR) 
	{
        closesocket (ConnectSocket);
        DEBUG_TOKEN_printf("Unable to connect to server: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
	//GET /api/channel/hls/projectsolo.m3u8?token={"user_id":null,"channel":"projectsolo","expires":1392910474,"chansub":{"view_until":1924905600,"restricted_bitrates":[]},"private":{"allowed_to_view":true},"privileged":false}&sig=6819357bd2c966938d5971a237ab723b462102fe HTTP/1.1
	// 1392910474 = 02 / 20 / 14 @ 3:34:34pm UTC
	// 1924905600 = 12 / 31 / 30 @ 12:00:00am UTC
	// HLS_TOKEN_URL = 'http://api.twitch.tv/api/channels/%s/access_token'
	// HLS_PLAYLIST_URL = 'http://usher.twitch.tv/api/channel/hls/%s.m3u8?token=%s&sig=%s'
#if 0
GET /api/channels/therainii/access_token HTTP/1.1
Accept: text/html, application/xhtml+xml, */*
Accept-Language: en-US
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)
Accept-Encoding: gzip, deflate
Host: api.twitch.tv
DNT: 1
Connection: Keep-Alive
*/

Bytes received: 512
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 21 Feb 2014 14:28:15 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 281
Connection: keep-alive
Status: 200 OK
X-API-Version: 3
WWW-Authenticate: OAuth realm='TwitchTV'
Cache-Control: max-age=0, private, must-revalidate
X-UA-Compatible: IE=Edge,chrome=1
ETag: "531d16e3d9c84af3765f5a5ac65a2bce"
X-Request-Id: e798600b146537c4a75f8d46d44b5f52
X-Runtime: 0.023911
Accept-Ranges: bytes
X-Varnish: 3679606203
Age: 0
Via: 1.1 varnish
X-MH-CBytes received: 325
ache: appcache1; M
Front-End-Https: off

{"token":"{\"user_id\":null,\"channel\":\"therainii\",\"expires\":1392994095,\"chansub\":{\"view_until\":1924905600,\"restricted_bitrates\":[]},\"private\":{\"allowed_to_view\":true},\"privileged\":false}","sig":"1b0a597af8e304466b2fae5a9d91fed590465f25","mobile_restricted":false}

#endif

//	sprintf_s( buffer, DEFAULT_BUFLEN, "GET /api/channels/%s/access_token HTTP/1.1\r\nAccept: text/html, application/xhtml+xml, */*\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)\r\nDNT: 1\r\nHost: api.twitch.tv\r\nConnection: Keep-Alive\r\n\r\n", TWITCH_CHANNEL_NAME );
	sprintf_s( buffer, DEFAULT_BUFLEN, "GET /api/channels/%s/access_token HTTP/1.1\r\nHost: api.twitch.tv\r\n\r\n", TWITCH_CHANNEL_NAME );
	
	DEBUG_TOKEN_printf("Sending data to get token : %s \n", buffer );

    iResult = send( ConnectSocket, buffer, (int)strlen(buffer), 0 );
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_TOKEN_printf("send failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    DEBUG_TOKEN_printf("Bytes Sent: %ld\n", iResult);

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_TOKEN_printf("shutdown failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    } 

    // Receive until the peer closes the connection
	int ReadSoFar = 0;
    do {

        iResult = recv(ConnectSocket, &buffer[ReadSoFar], recvbuflen - ReadSoFar, 0);
        if ( iResult > 0 )
		{
			ReadSoFar += iResult;
            DEBUG_TOKEN_printf("Bytes received: %d\n", iResult);
			for( int i=0;i<iResult;i++)
				DEBUG_TOKEN_printf("%c",buffer[i]);
		}
        else if ( iResult == 0 )
            DEBUG_TOKEN_printf("Connection closed\n");
        else
            DEBUG_TOKEN_printf("recv failed: %d\n", WSAGetLastError());

    } while( iResult > 0 && ReadSoFar < recvbuflen );
    // cleanup
    closesocket(ConnectSocket);

	//
//	char Resp[ DEFAULT_BUFLEN ];
//	urldecode( Resp, buffer, 1 );
//	Resp[ ReadSoFar ] = 0;
//	DEBUG_TOKEN_printf("Decoded response: %s\n", Resp);

	//extract Token
	//{"token":"{\"user_id\":null,\"channel\":\"therainii\",\"expires\":1392994095,\"chansub\":{\"view_until\":1924905600,\"restricted_bitrates\":[]},\"private\":{\"allowed_to_view\":true},\"privileged\":false}","sig":"1b0a597af8e304466b2fae5a9d91fed590465f25","mobile_restricted":false}
//	char Token[ DEFAULT_BUFLEN ];
	int TokenLen = 0;
	char *TokenStart = strstr( buffer, "{\"token\":\"" );
	char *TokenEnd = strstr( buffer, "\",\"sig\"" );
	if( TokenStart != buffer && TokenStart != NULL )
	{
		TokenStart += strlen( "{\"token\":\"" );
		for( TokenLen=0;TokenLen<ReadSoFar && TokenStart != TokenEnd && *TokenStart != 0; TokenLen++, TokenStart++ )
			Token[ TokenLen ] = *TokenStart;
	}
	Token[ TokenLen ] = 0;

//	char Sig[ DEFAULT_BUFLEN ];
	int SigLen = 0;
	char *SigStart = strstr( buffer, "\",\"sig\":\"" );
	if( SigStart != buffer && SigStart != NULL )
	{
		SigStart += strlen( "\",\"sig\":\"" );
		for( SigLen=0;SigLen<ReadSoFar && *SigStart != 0 && *SigStart != '"'; SigLen++, SigStart++ )
			Sig[ SigLen ] = *SigStart;
	}
	Sig[ SigLen ] = 0;


	return 0;
}

int GetTwitchFragmentURL( char *Token, char *Sig, char *JsonResp )
{
    //----------------------
    // Declare and initialize variables.
    int iResult;

    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService; 

//    char *sendbuf = "this is a test";
    char buffer[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
  
    //----------------------
    // Create a SOCKET for connecting to server
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) 
	{
        DEBUG_URL_printf("Error at socket(): %ld\n", WSAGetLastError() );
        WSACleanup();
        return 1;
    }

 
    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port of the server to be connected to.
    clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = TwitchUsherIPAddr.s_addr;
    clientService.sin_port = htons( 80 );

    //----------------------
    // Connect to server.
    iResult = connect( ConnectSocket, (SOCKADDR*) &clientService, sizeof(clientService) );
    if ( iResult == SOCKET_ERROR) 
	{
        closesocket (ConnectSocket);
        DEBUG_URL_printf("Unable to connect to server: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
	//GET /api/channel/hls/projectsolo.m3u8?token={"user_id":null,"channel":"projectsolo","expires":1392910474,"chansub":{"view_until":1924905600,"restricted_bitrates":[]},"private":{"allowed_to_view":true},"privileged":false}&sig=6819357bd2c966938d5971a237ab723b462102fe HTTP/1.1
	// 1392910474 = 02 / 20 / 14 @ 3:34:34pm UTC
	// 1924905600 = 12 / 31 / 30 @ 12:00:00am UTC
	// HLS_TOKEN_URL = 'http://api.twitch.tv/api/channels/%s/access_token'
	// HLS_PLAYLIST_URL = 'http://usher.twitch.tv/api/channel/hls/%s.m3u8?token=%s&sig=%s'
#if 0
LIVESTREAMER : 

GET /find/therainii.json?p=655946&nauthsig=a16fbe836b1632a30681fe30738be2af52db2bc0&type=any&nauth=%7B%22user_id%22%3Anull%2C%22channel%22%3A%22therainii%22%2C%22expires%22%3A1392997817%2C%22chansub%22%3A%7B%22view_until%22%3A1924905600%2C%22restricted_bitrates%22%3A%5B%5D%7D%2C%22private%22%3A%7B%22allowed_to_view%22%3Atrue%7D%2C%22privileged%22%3Afalse%7D&private_code=null HTTP/1.1
Host: usher.twitch.tv
Accept-Encoding: gzip, deflate, compress
User-Agent: python-requests/2.0.0 CPython/2.7.3 Windows/7

ME :
GET /find/therainii.json?nauthsig=8522583d2565282473372f73f950cd258c855538&type=any&nauth=%7B%22user_id%22%3Anull%2C%22channel%22%3A%22therainii%22%2C%22expires%22%3A1392998340%2C%22chansub%22%3A%7B%22view_until%22%3A1924905600%2C%22restricted_bitrates%22%3A%5B%5D%7D%2C%22private%22%3A%7B%22allowed_to_view%22%3Atrue%7D%2C%22privileged%22%3Afalse%7D&private_code=null HTTP/1.1
Host: usher.twitch.tv

Bytes received: 512
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 21 Feb 2014 14:28:15 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 281
Connection: keep-alive
Status: 200 OK
X-API-Version: 3
WWW-Authenticate: OAuth realm='TwitchTV'
Cache-Control: max-age=0, private, must-revalidate
X-UA-Compatible: IE=Edge,chrome=1
ETag: "531d16e3d9c84af3765f5a5ac65a2bce"
X-Request-Id: e798600b146537c4a75f8d46d44b5f52
X-Runtime: 0.023911
Accept-Ranges: bytes
X-Varnish: 3679606203
Age: 0
Via: 1.1 varnish
X-MH-CBytes received: 325
ache: appcache1; M
Front-End-Https: off

{"token":"{\"user_id\":null,\"channel\":\"therainii\",\"expires\":1392994095,\"chansub\":{\"view_until\":1924905600,\"restricted_bitrates\":[]},\"private\":{\"allowed_to_view\":true},\"privileged\":false}","sig":"1b0a597af8e304466b2fae5a9d91fed590465f25","mobile_restricted":false}

#endif

	char *UrlEncodedToken = url_encode( Token, true );
	DEBUG_URL_printf("\n\n Encoded Token to get URL : %s \n", UrlEncodedToken );

//	sprintf_s( buffer, DEFAULT_BUFLEN, "GET /api/channel/hls/%s.m3u8?token=%s&sig=%s HTTP/1.1\r\nHost: usher.justin.tv\r\n\r\n", TWITCH_CHANNEL_NAME, Token, Sig );
	sprintf_s( buffer, DEFAULT_BUFLEN, "GET /select/%s.json?allow_source=true&nauthsig=%s&nauth=%s&type=any HTTP/1.1\r\nHost: usher.justin.tv\r\n\r\n", TWITCH_CHANNEL_NAME, Sig, UrlEncodedToken );
//	sprintf_s( buffer, DEFAULT_BUFLEN, "GET /find/%s.json?nauthsig=%s&type=any&nauth=%s&private_code=null HTTP/1.1\r\nHost: usher.twitch.tv\r\n\r\n", TWITCH_CHANNEL_NAME, Sig, UrlEncodedToken );
//	sprintf_s( buffer, DEFAULT_BUFLEN, "GET /find/%s.json?p=655946&nauthsig=%s&type=any&nauth=%s&private_code=null HTTP/1.1\r\nHost: usher.twitch.tv\r\n\r\n", TWITCH_CHANNEL_NAME, Sig, UrlEncodedToken );
//	sprintf_s( buffer, DEFAULT_BUFLEN, "GET /find/%s.json?nauthsig=%s&type=any&nauth=%s&private_code=null HTTP/1.1\r\nHost: usher.twitch.tv\r\nAccept-Encoding: gzip, deflate, compress\r\nUser-Agent: python-requests/2.0.0 CPython/2.7.3 Windows/7\r\n\r\n", TWITCH_CHANNEL_NAME, Sig, UrlEncodedToken );
	DEBUG_URL_printf("\n\nSending data to get URL : \n%s \n", buffer );

    iResult = send( ConnectSocket, buffer, (int)strlen(buffer), 0 );
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_URL_printf("send failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    DEBUG_URL_printf("Bytes Sent: %ld\n", iResult);

    // Receive until the peer closes the connection
	int ReadSoFar = 0;
//    do {
        iResult = recv(ConnectSocket, &buffer[ReadSoFar], recvbuflen - ReadSoFar, 0);
        if ( iResult > 0 )
		{
			ReadSoFar += iResult;
            DEBUG_URL_printf("Bytes received: %d\n", iResult);
			for( int i=0;i<iResult;i++)
				DEBUG_URL_printf("%c",buffer[i]);
		}
        else if ( iResult == 0 )
            DEBUG_URL_printf("Connection closed\n");
        else
            DEBUG_URL_printf("recv failed: %d\n", WSAGetLastError());

//    } while( iResult > 0 && ReadSoFar < recvbuflen );

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_URL_printf("shutdown failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }/**/

    // cleanup
    closesocket(ConnectSocket);

/*
#EXTM3U
#EXT-X-TWITCH-INFO:NODE="video11.iad02",MANIFEST-NODE="video11.iad02",SERVER-TIME="1393009587.53",USER-IP="79.116.217.103",CLUSTER="iad02",MANIFEST-CLUSTER="iad02"
#EXT-X-MEDIA:TYPE=VIDEO,GROUP-ID="chunked",NAME="Source",AUTOSELECT=YES,DEFAULT=YES
#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=1691828,RESOLUTION=1920x1080,VIDEO="chunked"
http://video11.iad02.hls.twitch.tv/hls77/projectsolo_8622018096_66462419/chunked/index-live.m3u8?token=id=7984089739829414210,bid=8622018096,exp=1393095987,node=video11-1.iad02.hls.justin.tv,nname=video11.iad02,fmt=chunked&sig=4dc6c3555e60dd6127382c1bdc4b0073fc98b861
*/

	//extract Url
	//{"token":"{\"user_id\":null,\"channel\":\"therainii\",\"expires\":1392994095,\"chansub\":{\"view_until\":1924905600,\"restricted_bitrates\":[]},\"private\":{\"allowed_to_view\":true},\"privileged\":false}","sig":"1b0a597af8e304466b2fae5a9d91fed590465f25","mobile_restricted":false}
//	char Token[ DEFAULT_BUFLEN ];
	int TokenLen = 0;
	JsonResp[ TokenLen ] = 0;
	char *TokenStart = strstr( buffer, "http://" );
	if( TokenStart != buffer && TokenStart != NULL )
	{
		char *TokenEnd = strstr( TokenStart, "#" );
		if( TokenEnd == NULL || TokenEnd == TokenStart )
			TokenEnd = &buffer[ReadSoFar];
		for( TokenLen=0;TokenLen<ReadSoFar && TokenStart != TokenEnd && *TokenStart != 0; TokenLen++, TokenStart++ )
			JsonResp[ TokenLen ] = *TokenStart;
	}
	JsonResp[ TokenLen ] = 0;
	DEBUG_URL_printf( "Possible Json : %s\n", JsonResp );

	return 0;
}


int GetTwitchM3UFileContent( char *Url, char *Host, char *TSResponse )
{
    //----------------------
    // Declare and initialize variables.
    int iResult;

    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService; 

//    char *sendbuf = "this is a test";
    char buffer[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

	struct in_addr TwitchContentIPAddr;
	GetTwitchIPs( Host, &TwitchContentIPAddr );

    //----------------------
    // Create a SOCKET for connecting to server
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) 
	{
        DEBUG_URL_printf("Error at socket(): %ld\n", WSAGetLastError() );
        WSACleanup();
        return 1;
    }

 
    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port of the server to be connected to.
    clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = TwitchContentIPAddr.s_addr;
    clientService.sin_port = htons( 80 );

    //----------------------
    // Connect to server.
    iResult = connect( ConnectSocket, (SOCKADDR*) &clientService, sizeof(clientService) );
    if ( iResult == SOCKET_ERROR) 
	{
        closesocket (ConnectSocket);
        DEBUG_URL_printf("Unable to connect to server: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }


	sprintf_s( buffer, DEFAULT_BUFLEN, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", Url, Host );
//	sprintf_s( buffer, DEFAULT_BUFLEN, "GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip, deflate, compress\r\nAccept: */*\r\nUser-Agent: python-requests/2.0.0 CPython/2.7.3 Windows/7\r\n\r\n", Url, Host );
	DEBUG_URL_printf("\n\nSending data to get URL : \n%s \n", buffer );

    iResult = send( ConnectSocket, buffer, (int)strlen(buffer), 0 );
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_URL_printf("send failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    DEBUG_URL_printf("Bytes Sent: %ld\n", iResult);

    // Receive until the peer closes the connection
	int ReadSoFar = 0;
	buffer[0] = 0;
    do {

        iResult = recv(ConnectSocket, &buffer[ReadSoFar], recvbuflen - ReadSoFar, 0);
        if ( iResult > 0 )
		{
			ReadSoFar += iResult;
            DEBUG_URL_printf("Bytes received: %d\n", iResult);
			for( int i=0;i<iResult;i++)
				DEBUG_URL_printf("%c",buffer[i]);
		}
        else if ( iResult == 0 )
            DEBUG_URL_printf("Connection closed\n");
        else
            DEBUG_URL_printf("recv failed: %d\n", WSAGetLastError());

    } while( iResult > 0 && ReadSoFar < recvbuflen 
		&& 1 == 0 
		);
	buffer[ReadSoFar] = 0;

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_URL_printf("shutdown failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }/**/

    // cleanup
    closesocket(ConnectSocket);

/*
Bytes received: 316
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:4
#EXT-X-MEDIA-SEQUENCE:2484
#EXTINF:4.000,
index-0000002484-Rnlj.ts
#EXTINF:4.000,
index-0000002485-30Ag.ts
#EXTINF:4.000,
index-0000002486-Avcx.ts
#EXTINF:4.000,
index-0000002487-37CH.ts
#EXTINF:4.000,
index-0000002488-r3VK.ts
#EXTINF:3.200,
index-0000002489-DvLk.ts
*/
	strcpy_s( TSResponse, DEFAULT_BUFLEN, buffer );
	return 0;
}


int BuildAndDownloadTSFiles2( char *Url, char *Host )
{
    //----------------------
    // Declare and initialize variables.
    int iResult;

    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService; 

//    char *sendbuf = "this is a test";
    char buffer[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

	struct in_addr TwitchContentIPAddr;
	GetTwitchIPs( Host, &TwitchContentIPAddr );

    //----------------------
    // Create a SOCKET for connecting to server
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) 
	{
        DEBUG_TS_printf("Error at socket(): %ld\n", WSAGetLastError() );
        WSACleanup();
        return 1;
    }

 
    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port of the server to be connected to.
    clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = TwitchContentIPAddr.s_addr;
    clientService.sin_port = htons( 80 );

    //----------------------
    // Connect to server.
    iResult = connect( ConnectSocket, (SOCKADDR*) &clientService, sizeof(clientService) );
    if ( iResult == SOCKET_ERROR) 
	{
        closesocket (ConnectSocket);
        DEBUG_TS_printf("Unable to connect to server: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }


//	sprintf_s( buffer, DEFAULT_BUFLEN, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", Url, Host );
	sprintf_s( buffer, DEFAULT_BUFLEN, "GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip, deflate, compress\r\nAccept: */*\r\nUser-Agent: python-requests/2.0.0 CPython/2.7.3 Windows/7\r\n\r\n", Url, Host );
	DEBUG_TS_printf("\n\nSending data to get URL : \n%s \n", buffer );

    iResult = send( ConnectSocket, buffer, (int)strlen(buffer), 0 );
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_TS_printf("send failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    DEBUG_TS_printf("Bytes Sent: %ld\n", iResult);

    // Receive until the peer closes the connection
	int ReadSoFar = 0;
	buffer[0] = 0;
    do {

        iResult = recv(ConnectSocket, &buffer[ReadSoFar], recvbuflen - ReadSoFar, 0);
        if ( iResult > 0 )
		{
			ReadSoFar += iResult;
            DEBUG_TS_printf("Bytes received: %d\n", iResult);
			for( int i=0;i<iResult;i++)
				DEBUG_TS_printf("%c",buffer[i]);
		}
        else if ( iResult == 0 )
            DEBUG_TS_printf("Connection closed\n");
        else
            DEBUG_TS_printf("recv failed: %d\n", WSAGetLastError());

    } while( iResult > 0 && ReadSoFar < recvbuflen );


    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) 
	{
        DEBUG_TS_printf("shutdown failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }/**/

    // cleanup
    closesocket(ConnectSocket);

	return 0;
}

std::set<int> RequestedLinks;
int AlreadyRequested = 0;

//#define ANTI_FLOOD_PROTECTION_LOOP_SLEEP 200
#define ANTI_FLOOD_PROTECTION_LOOP_SLEEP 1

void BuildAndDownloadTSFiles( char *Url, char *Host, char *TSResponse )
{
/*
http://video11.iad02.hls.twitch.tv/hls77/projectsolo_8622018096_66462419/chunked/.....

Bytes received: 316
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:4
#EXT-X-MEDIA-SEQUENCE:2484
#EXTINF:4.000,
index-0000002484-Rnlj.ts
#EXTINF:4.000,
index-0000002485-30Ag.ts
#EXTINF:4.000,
index-0000002486-Avcx.ts
#EXTINF:4.000,
index-0000002487-37CH.ts
#EXTINF:4.000,
index-0000002488-r3VK.ts
#EXTINF:3.200,
index-0000002489-DvLk.ts


/hls77/projectsolo_8622018096_66462419/chunked/
*/
	//extract chunked url
	char UrlChunk[ DEFAULT_BUFLEN ];
	UrlChunk[ 0 ] =0;
	{
		char *t = UrlChunk;
		char *UrlStart = Url;
		char *UrlEnd = strstr( Url, "/chunked/" );
		if( UrlEnd != NULL && UrlEnd != Url )
		{
			UrlEnd += strlen( "/chunked/" );
			for( ;UrlStart<UrlEnd;UrlStart++ )
			{
				*t = *UrlStart;
				t++;
			}
			*t = 0;
		}
		else
		{
			return;
		}
	}

	int StartStamp = GetTickCount();

	//extract the list of TS files
	char *SafetyBelt = TSResponse + DEFAULT_BUFLEN;
	char *PrevStart = NULL;
	char *NextFileStart = strstr( TSResponse, "index" );
	int ActualRequestsMade = 0;
	while( NextFileStart != NULL && NextFileStart != PrevStart )
	{
		char *NextFileEnd = strstr( NextFileStart, ".ts" );
		if( NextFileEnd == NULL || NextFileEnd > SafetyBelt )
			NextFileEnd = SafetyBelt;
		else
			NextFileEnd += strlen( ".ts" );
		PrevStart = NextFileStart;

		//copy bytes out
		char FileName[ DEFAULT_BUFLEN ];
		char *t = FileName;
		for( ;NextFileStart<NextFileEnd;NextFileStart++ )
		{
			*t = *NextFileStart;
			t++;
		}
		*t = 0;
		//gen full link
		char FullLink[ DEFAULT_BUFLEN ];
		sprintf_s( FullLink, "%s%s", UrlChunk, FileName );
		int crc = crc32( (const unsigned char *)FullLink, strlen( FullLink ) );
//		int crc = crc32( (const unsigned char *)FileName, strlen( FileName ) );
		if( 1 || RequestedLinks.find( crc ) == RequestedLinks.end() )
		{
			RequestedLinks.insert( crc );
			DEBUG_TSList_printf( "%d-%d)trying to fetch : %s%s\n", GlobalPrintCounter, AlreadyRequested, Host, FullLink );
			GlobalPrintCounter++;
			//should be like 15k / frame ?
			int InnerStartStamp = GetTickCount();
			BuildAndDownloadTSFiles2( FullLink, Host );
			int InnerEndStamp = GetTickCount();
			if( InnerEndStamp - InnerStartStamp < ANTI_FLOOD_PROTECTION_LOOP_SLEEP )
				Sleep( ANTI_FLOOD_PROTECTION_LOOP_SLEEP - ( InnerEndStamp - InnerStartStamp ) );
			ActualRequestsMade++;
		}
		else
		{
			AlreadyRequested++;
			Sleep( 20 );
		}

		NextFileStart = strstr( NextFileEnd, "index" );
	}
	if( ActualRequestsMade == 0 )
		Sleep( 100 );
	int EndStamp = GetTickCount();
	if( EndStamp - StartStamp < ANTI_FLOOD_PROTECTION_LOOP_SLEEP )
		Sleep( ANTI_FLOOD_PROTECTION_LOOP_SLEEP - ( EndStamp - StartStamp ) );
}

std::string TwitchGetJsonWithLivestreamer() 
{
	char cmd[ DEFAULT_BUFLEN ];
	sprintf_s( cmd, DEFAULT_BUFLEN, "\"c:\\Program Files (x86)\\Livestreamer\\livestreamer.exe\" -j http://www.twitch.tv/%s worst", TWITCH_CHANNEL_NAME );
    FILE* pipe = _popen( cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
    while(!feof(pipe))
	{
    	if(fgets(buffer, 128, pipe) != NULL)
    		result += buffer;
    }
    _pclose(pipe);
    return result;
}


void GetTwitchFragmentURLFromJson( const char *JsonResp, char *Url )
{
/*
{
  "headers": {
    "Content-Length": "0"
  },
  "type": "hls",
  "url": "http://video15.ord01.hls.twitch.tv/hls49/therainii_8620288176_66410743/chunked/index-live.m3u8?token=id=5867774166813405362,bid=8620288176,exp=1393083019,node=video15-1.ord01.hls.justin.tvname=video15.ord01,fmt=chunked&sig=683d8f4ad9569494f45e86af3dea84a7f02f7f72"
}
*/
	*Url = 0;
	char *UrlStart = strstr( (char*)JsonResp, "\"url\": \"" );
	if( UrlStart != NULL && UrlStart != JsonResp )
	{
		UrlStart += strlen( "\"url\": \"" );
		strcpy_s( Url, DEFAULT_BUFLEN, UrlStart );
	}
	int Len = (int)strlen( Url );
//	for( int i=Len; i > 0; i-- )
	for( int i=0; i < Len; i++ )
	{
		if( Url[i] == '"' )
		{
			Url[i] = 0;
			break;
		}
//		Url[i] = 0;
	}
}

void GetTwitchHostFromUrl( const char *Url, char *Host )
{
/*
http://video15.ord01.hls.twitch.tv/hls49
*/
	*Host = 0;
	char *UrlStart = strstr( (char*)Url, "http://" );
	if( UrlStart != NULL )
	{
		UrlStart += strlen( "http://" );
		char *UrlEnd = strstr( (char*)UrlStart, "/" );
		for( ;UrlStart!=UrlEnd;UrlStart++)
		{
			*Host = *UrlStart;
			Host++;
		}
		*Host = 0;
	}
}


void GetTwitchNoHostFromUrl( const char *Url, char *NoHostUrl )
{
/*
http://video15.ord01.hls.twitch.tv/hls49
*/
	*NoHostUrl = 0;
	char *UrlStart = strstr( (char*)Url, "http://" );
	if( UrlStart != NULL )
	{
		UrlStart += strlen( "http://" );
		UrlStart = strstr( (char*)UrlStart, "/" );
		if( UrlStart != NULL )
			strcpy_s( NoHostUrl, DEFAULT_BUFLEN, UrlStart );
	}
}

#define MAX_THREADS 1

DWORD WINAPI OneThreadJob( LPVOID lpParam )
{
	int Counter = 0;
	char NoHostUrl[ DEFAULT_BUFLEN ];
	do
	{
		//do it for every fragment
		char Token[ DEFAULT_BUFLEN ];
		char Sig[ DEFAULT_BUFLEN ];
		GetTwitchToken( Token, Sig );

		//do it for every token / sig combo
		char JSon[ DEFAULT_BUFLEN ];
		GetTwitchFragmentURL( Token, Sig, JSon );

		char Host[ DEFAULT_BUFLEN ];
		GetTwitchHostFromUrl( JSon, Host );
		DEBUG_Main_printf(" Could be the host %s\n", Host );

//		char NoHostUrl[ DEFAULT_BUFLEN ];
		GetTwitchNoHostFromUrl( JSon, NoHostUrl );
		DEBUG_Main_printf(" Could be the naked url %s\n", NoHostUrl );

		char TSListResponse[ DEFAULT_BUFLEN ];
		GetTwitchM3UFileContent( NoHostUrl, Host, TSListResponse );
		DEBUG_Main_printf(" Could be the TS list response %s\n", TSListResponse );

//		BuildAndDownloadTSFiles( NoHostUrl, Host, TSListResponse );

		printf("%d) Could be the naked url %s\n", Counter++, NoHostUrl );
	}while( 1 && strlen( NoHostUrl ) > 0 );
	return 0;
}

DWORD WINAPI OneThreadJob2( LPVOID lpParam )
{
	do
	{
		//do it for every fragment
		std::string str = TwitchGetJsonWithLivestreamer();
		DEBUG_Main_printf(" Could be the json %s\n", str.c_str() );

		char Url[ DEFAULT_BUFLEN ];
		GetTwitchFragmentURLFromJson( str.c_str(), Url );
		DEBUG_Main_printf(" Could be the url %s\n", Url );

		char Host[ DEFAULT_BUFLEN ];
		GetTwitchHostFromUrl( Url, Host );
		DEBUG_Main_printf(" Could be the host %s\n", Host );

		char NoHostUrl[ DEFAULT_BUFLEN ];
		GetTwitchNoHostFromUrl( Url, NoHostUrl );
		DEBUG_Main_printf(" Could be the naked url %s\n", NoHostUrl );

		char TSListResponse[ DEFAULT_BUFLEN ];
		GetTwitchM3UFileContent( NoHostUrl, Host, TSListResponse );

//		BuildAndDownloadTSFiles( NoHostUrl, Host, TSListResponse );

		printf(" Could be the naked url %s\n", NoHostUrl );
	}while( 1 );
	return 0;
}


int __cdecl main()
{
    //----------------------
    // Declare and initialize variables.
    WSADATA wsaData;
    int iResult;
 
    //----------------------
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != NO_ERROR)
	{
      printf("WSAStartup failed: %d\n", iResult);
      return 1;
    }

/*	{
		//do it once
		GetTwitchIPs( "api.twitch.tv", &TwitchTokenIPAddr );
		GetTwitchIPs( "usher.twitch.tv", &TwitchUsherIPAddr );
		OneThreadJob( NULL );
	}/**/
	{
		//do it once
		GetTwitchIPs( "api.twitch.tv", &TwitchTokenIPAddr );
		GetTwitchIPs( "usher.twitch.tv", &TwitchUsherIPAddr );

		DWORD   dwThreadIdArray[MAX_THREADS];
		HANDLE  hThreadArray[MAX_THREADS]; 

		for( int i=0;i<MAX_THREADS;i++)
		{
			hThreadArray[i] = CreateThread( 
				NULL,                   // default security attributes
				0,                      // use default stack size  
				OneThreadJob,			// thread function name
				0,						// argument to thread function 
				0,                      // use default creation flags 
				&dwThreadIdArray[i]);   // returns the thread identifier 


			// Check the return value for success.
			// If CreateThread fails, terminate execution. 
			// This will automatically clean up threads and memory. 

			if (hThreadArray[i] == NULL) 
			{
			   ExitProcess(3);
			}
		}
		WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);

		// Close all thread handles and free memory allocations.
		for(int i=0; i<MAX_THREADS; i++)
			CloseHandle(hThreadArray[i]);

	}/**/
/*	{
		//do it once
		GetTwitchIPs( "api.twitch.tv", &TwitchTokenIPAddr );
		GetTwitchIPs( "usher.twitch.tv", &TwitchUsherIPAddr );

		DWORD   dwThreadIdArray[MAX_THREADS];
		HANDLE  hThreadArray[MAX_THREADS]; 

		for( int i=0;i<MAX_THREADS;i++)
		{
			hThreadArray[i] = CreateThread( 
				NULL,                   // default security attributes
				0,                      // use default stack size  
				OneThreadJob2,			// thread function name
				0,						// argument to thread function 
				0,                      // use default creation flags 
				&dwThreadIdArray[i]);   // returns the thread identifier 


			// Check the return value for success.
			// If CreateThread fails, terminate execution. 
			// This will automatically clean up threads and memory. 

			if (hThreadArray[i] == NULL) 
			{
			   ExitProcess(3);
			}
		}
		WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);

		// Close all thread handles and free memory allocations.
		for(int i=0; i<MAX_THREADS; i++)
			CloseHandle(hThreadArray[i]);

	}/**/
/*	{
		std::string str = TwitchGetJsonWithLivestreamer();
		printf(" Could be the json %s\n", str.c_str() );

		char Url[ DEFAULT_BUFLEN ];
		GetTwitchFragmentURLFromJson( str.c_str(), Url );
		printf(" Could be the url %s\n", Url );

		char Host[ DEFAULT_BUFLEN ];
		GetTwitchHostFromUrl( Url, Host );
		printf(" Could be the host %s\n", Host );

		char NoHostUrl[ DEFAULT_BUFLEN ];
		GetTwitchNoHostFromUrl( Url, NoHostUrl );
		printf(" Could be the naked url %s\n", NoHostUrl );

		char TSListResponse[ DEFAULT_BUFLEN ];
		GetTwitchM3UFileContent( NoHostUrl, Host, TSListResponse );
	}/**/

    WSACleanup();

    return 0;
}