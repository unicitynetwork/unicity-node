// Mock miniupnpc header for testing
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// API version for compatibility macros
#define MINIUPNPC_API_VERSION 18

// Device list structure
struct UPNPDev {
    char* descURL;
    char* st;
    struct UPNPDev* pNext;
};

// URLs structure
struct UPNPUrls {
    char* controlURL;
    char* ipcondescURL;
    char* controlURL_CIF;
    char* controlURL_6FC;
    char* rootdescURL;
};

// Service data structure
struct IGDdatas_service {
    char servicetype[128];
    char controlurl[256];
    char eventsuburl[256];
    char scpdurl[256];
};

// IGD data structure
struct IGDdatas {
    char cureltname[64];
    char urlbase[128];
    char presentationurl[128];
    int level;
    struct IGDdatas_service CIF;
    struct IGDdatas_service first;
    struct IGDdatas_service second;
    struct IGDdatas_service IPv6FC;
    struct IGDdatas_service tmp;
};

// Discovery function
struct UPNPDev* upnpDiscover(int delay, const char* multicastif,
                             const char* minissdpdsock, int localport,
                             int ipv6, unsigned char ttl, int* error);

// Get valid IGD (API version 18+)
int UPNP_GetValidIGD(struct UPNPDev* devlist, struct UPNPUrls* urls,
                     struct IGDdatas* data, char* lanaddr, int lanaddrlen,
                     char* wanaddr, int wanaddrlen);

// Free device list
void freeUPNPDevlist(struct UPNPDev* devlist);

// Free URLs
void FreeUPNPUrls(struct UPNPUrls* urls);

#ifdef __cplusplus
}
#endif
