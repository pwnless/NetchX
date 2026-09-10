#pragma once
#ifndef IPEVENTHANDLER_H
#define IPEVENTHANDLER_H
#include "Based.h"

namespace IPHandler
{
	bool INIT();
	void FREE();

	// Dependency-injection seam used by the native regression test.  The
	// production path leaves both callbacks unset and calls NetFilterSDK.
	using PacketPostCallback = NF_STATUS(*)(const char*, int, PNF_IP_PACKET_OPTIONS);
	void SetPostCallbacksForTesting(PacketPostCallback postSend, PacketPostCallback postReceive);
}

void ipSend(const char* buffer, int length, PNF_IP_PACKET_OPTIONS options);
void ipReceive(const char* buffer, int length, PNF_IP_PACKET_OPTIONS options);

#endif
