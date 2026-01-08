// Mock upnpcommands header for testing
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Success return code
#define UPNPCOMMAND_SUCCESS 0

// Get external IP address
int UPNP_GetExternalIPAddress(const char* controlURL, const char* servicetype,
                               char* extIpAdd);

// Add port mapping
int UPNP_AddPortMapping(const char* controlURL, const char* servicetype,
                        const char* extPort, const char* inPort,
                        const char* inClient, const char* desc,
                        const char* proto, const char* remoteHost,
                        const char* leaseDuration);

// Delete port mapping
int UPNP_DeletePortMapping(const char* controlURL, const char* servicetype,
                           const char* extPort, const char* proto,
                           const char* remoteHost);

#ifdef __cplusplus
}
#endif
