#include "IPEventHandler.h"

#include <array>

DWORD icmping = 0;

namespace
{
	mutex receiveLock;
	condition_variable receiveReady;
	int receiveCount = 0;
	array<array<char, 28>, 3> receivedPackets{};
	array<chrono::steady_clock::time_point, 3> receivedAt{};
}

extern "C" NF_STATUS __cdecl TestIpPostSend(const char*, int, PNF_IP_PACKET_OPTIONS)
{
	return NF_STATUS_FAIL;
}

extern "C" NF_STATUS __cdecl TestIpPostReceive(const char* buffer, int length, PNF_IP_PACKET_OPTIONS options)
{
	if (buffer == NULL || options == NULL || length != static_cast<int>(receivedPackets[0].size()) ||
		options->ip_family != AF_INET || options->ipHeaderSize != 20)
		return NF_STATUS_FAIL;

	{
		lock_guard<mutex> lock(receiveLock);
		if (receiveCount >= static_cast<int>(receivedPackets.size()))
			return NF_STATUS_FAIL;
		memcpy(receivedPackets[receiveCount].data(), buffer, receivedPackets[receiveCount].size());
		receivedAt[receiveCount] = chrono::steady_clock::now();
		++receiveCount;
	}
	receiveReady.notify_all();
	return NF_STATUS_SUCCESS;
}

int main()
{
	array<char, 28> echo{};
	echo[0] = 0x45;
	echo[2] = 0x00;
	echo[3] = 0x1c;
	echo[8] = 64;
	echo[9] = IPPROTO_ICMP;
	echo[12] = static_cast<char>(192);
	echo[13] = 0;
	echo[14] = 2;
	echo[15] = 1;
	echo[16] = 8;
	echo[17] = 8;
	echo[18] = 8;
	echo[19] = 8;
	echo[20] = 0x08;
	echo[24] = 0x12;
	echo[25] = 0x34;

	NF_IP_PACKET_OPTIONS options{};
	options.ip_family = AF_INET;
	options.ipHeaderSize = 20;

	IPHandler::SetPostCallbacksForTesting(TestIpPostSend, TestIpPostReceive);
	bool passed = IPHandler::INIT();
	icmping = 200;
	const auto callbackStarted = chrono::steady_clock::now();
	ipSend(echo.data(), static_cast<int>(echo.size()), &options);
	const auto callbackElapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - callbackStarted);

	{
		unique_lock<mutex> lock(receiveLock);
		passed = passed && receiveReady.wait_for(lock, chrono::seconds(2), [] { return receiveCount == 1; });
	}
	const auto responseElapsed = chrono::duration_cast<chrono::milliseconds>(receivedAt[0] - callbackStarted);
	passed = passed && callbackElapsed < chrono::milliseconds(100) && responseElapsed >= chrono::milliseconds(150) &&
		receivedPackets[0][20] == 0x00 && receivedPackets[0][12] == 8 && receivedPackets[0][13] == 8 &&
		receivedPackets[0][14] == 8 && receivedPackets[0][15] == 8 && static_cast<unsigned char>(receivedPackets[0][16]) == 192 &&
		receivedPackets[0][17] == 0 && receivedPackets[0][18] == 2 && receivedPackets[0][19] == 1;

	// A later packet with a shorter requested delay must not wait behind the
	// already queued 5-second reply.  This protects deadline ordering when a
	// caller updates AIO_ICMPING at runtime.
	icmping = 5000;
	ipSend(echo.data(), static_cast<int>(echo.size()), &options);
	this_thread::sleep_for(chrono::milliseconds(20));
	icmping = 100;
	echo[24] = 0x56;
	echo[25] = 0x78;
	const auto shortDelayStarted = chrono::steady_clock::now();
	ipSend(echo.data(), static_cast<int>(echo.size()), &options);
	{
		unique_lock<mutex> lock(receiveLock);
		passed = passed && receiveReady.wait_for(lock, chrono::seconds(2), [] { return receiveCount == 2; });
	}
	const auto shortDelayElapsed = chrono::duration_cast<chrono::milliseconds>(receivedAt[1] - shortDelayStarted);
	passed = passed && shortDelayElapsed >= chrono::milliseconds(50) && shortDelayElapsed < chrono::seconds(1) &&
		receivedPackets[1][24] == 0x56 && receivedPackets[1][25] == 0x78;

	const auto stopStarted = chrono::steady_clock::now();
	IPHandler::FREE();
	IPHandler::SetPostCallbacksForTesting(nullptr, nullptr);
	const auto stopElapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - stopStarted);
	passed = passed && stopElapsed < chrono::seconds(1) && receiveCount == 2;

	printf("IP delayed ICMP regression: %s (%d ms callback, %d ms first response, %d ms reordered response, %d ms shutdown)\n", passed ? "PASS" : "FAIL",
		static_cast<int>(callbackElapsed.count()), static_cast<int>(responseElapsed.count()), static_cast<int>(shortDelayElapsed.count()), static_cast<int>(stopElapsed.count()));
	return passed ? 0 : 1;
}
