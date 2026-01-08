// Mock implementation of miniupnpc functions for testing
// This file provides stub implementations that read from mock state

#include "mock_upnp.hpp"
#include "miniupnpc/miniupnpc.h"
#include "miniupnpc/upnpcommands.h"
#include <cstring>
#include <cstdlib>

using namespace unicity::test;

extern "C" {

// upnpDiscover - returns device list or nullptr
UPNPDev* upnpDiscover(int delay, const char* multicastif, const char* minissdpdsock,
                      int localport, int ipv6, unsigned char ttl, int* error) {
    auto& mock = GetUPnPMock();
    mock.discover_calls++;

    if (error) *error = mock.discover_error_code;

    if (!mock.discover_success) {
        return nullptr;
    }

    // Return a dummy device
    UPNPDev* dev = (UPNPDev*)malloc(sizeof(UPNPDev));
    dev->descURL = strdup("http://192.168.1.1:5000/rootDesc.xml");
    dev->st = strdup("urn:schemas-upnp-org:device:InternetGatewayDevice:1");
    dev->pNext = nullptr;
    return dev;
}

// UPNP_GetValidIGD - validate and get IGD info (API version 18+)
// Returns: 0=no IGD, 1=valid connected IGD, 2=valid not connected, 3=not valid
int UPNP_GetValidIGD(UPNPDev* devlist, UPNPUrls* urls, IGDdatas* data,
                     char* lanaddr, int lanaddrlen, char* wanaddr, int wanaddrlen) {
    auto& mock = GetUPnPMock();
    mock.get_igd_calls++;

    if (wanaddr && wanaddrlen > 0) wanaddr[0] = '\0';

    if (mock.igd_result != 1) {
        return mock.igd_result;
    }

    // Fill in mock data
    urls->controlURL = strdup(mock.control_url.c_str());
    strncpy(data->first.servicetype, mock.service_type.c_str(), sizeof(data->first.servicetype) - 1);
    data->first.servicetype[sizeof(data->first.servicetype) - 1] = '\0';
    strncpy(lanaddr, mock.lan_addr.c_str(), lanaddrlen - 1);
    lanaddr[lanaddrlen - 1] = '\0';

    return 1;
}

// UPNP_GetExternalIPAddress
int UPNP_GetExternalIPAddress(const char* controlURL, const char* servicetype,
                               char* extIpAdd) {
    auto& mock = GetUPnPMock();
    mock.get_external_ip_calls++;

    if (!mock.get_external_ip_success) {
        extIpAdd[0] = '\0';
        return -1;
    }

    strncpy(extIpAdd, mock.external_ip.c_str(), 39);
    extIpAdd[39] = '\0';
    return UPNPCOMMAND_SUCCESS;
}

// UPNP_AddPortMapping
int UPNP_AddPortMapping(const char* controlURL, const char* servicetype,
                        const char* extPort, const char* inPort,
                        const char* inClient, const char* desc,
                        const char* proto, const char* remoteHost,
                        const char* leaseDuration) {
    auto& mock = GetUPnPMock();
    mock.add_mapping_calls++;

    if (!mock.add_mapping_success) {
        return mock.add_mapping_error ? mock.add_mapping_error : 718;
    }

    return UPNPCOMMAND_SUCCESS;
}

// UPNP_DeletePortMapping
int UPNP_DeletePortMapping(const char* controlURL, const char* servicetype,
                           const char* extPort, const char* proto,
                           const char* remoteHost) {
    auto& mock = GetUPnPMock();
    mock.delete_mapping_calls++;

    return mock.delete_mapping_success ? UPNPCOMMAND_SUCCESS : -1;
}

// freeUPNPDevlist
void freeUPNPDevlist(UPNPDev* devlist) {
    while (devlist) {
        UPNPDev* next = devlist->pNext;
        free(devlist->descURL);
        free(devlist->st);
        free(devlist);
        devlist = next;
    }
}

// FreeUPNPUrls
void FreeUPNPUrls(UPNPUrls* urls) {
    if (urls) {
        free(urls->controlURL);
        urls->controlURL = nullptr;
    }
}

}  // extern "C"
