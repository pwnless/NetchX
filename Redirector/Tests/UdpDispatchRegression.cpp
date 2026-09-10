#include "EventHandler.h"

#include <array>
#include <future>

extern bool filterParent;
extern bool filterTCP;
extern bool filterUDP;
extern bool filterDNS;
extern bool dnsOnly;
extern wstring tgtHost;
extern wstring tgtPort;
extern string tgtUsername;
extern string tgtPassword;
extern vector<wregex> handleList;
extern vector<wregex> bypassList;

namespace
{
	constexpr ENDPOINT_ID FirstEndpoint = 4321;
	// This exceeds the shared IOCP worker count and verifies that many active
	// SOCKS UDP associations do not require one receiver thread each.
	constexpr int PacketCount = 48;

	mutex receiveLock;
	condition_variable receiveReady;
	array<bool, PacketCount> received{};
	int receiveCount = 0;

	bool ReceiveExact(SOCKET socket, char* buffer, int length)
	{
		for (int receivedLength = 0; receivedLength < length;)
		{
			const int result = recv(socket, buffer + receivedLength, length - receivedLength, 0);
			if (result <= 0)
				return false;
			receivedLength += result;
		}
		return true;
	}

	SOCKET CreateLoopbackSocket(int type, USHORT& port)
	{
		const SOCKET socket = ::socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
		if (socket == INVALID_SOCKET)
			return INVALID_SOCKET;

		SOCKADDR_IN address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (::bind(socket, reinterpret_cast<PSOCKADDR>(&address), sizeof(address)) == SOCKET_ERROR)
		{
			closesocket(socket);
			return INVALID_SOCKET;
		}

		int addressLength = sizeof(address);
		if (getsockname(socket, reinterpret_cast<PSOCKADDR>(&address), &addressLength) == SOCKET_ERROR)
		{
			closesocket(socket);
			return INVALID_SOCKET;
		}
		port = address.sin_port;
		return socket;
	}

	bool SendUdpReply(SOCKET relay, const SOCKADDR_IN& client, int clientLength, char sequence)
	{
		const array<char, 11> reply = {
			0x00, 0x00, 0x00, 0x01,
			0x08, 0x08, 0x08, 0x08,
			0x23, 0x28,
			sequence
		};
		return sendto(relay, reply.data(), static_cast<int>(reply.size()), 0,
			reinterpret_cast<const SOCKADDR*>(&client), clientLength) == static_cast<int>(reply.size());
	}

	bool WaitForReceives()
	{
		unique_lock<mutex> lock(receiveLock);
		return receiveReady.wait_for(lock, chrono::seconds(5), [] { return receiveCount == PacketCount; });
	}
}

extern "C" NF_STATUS __cdecl TestUdpPostReceive(ENDPOINT_ID id, const unsigned char* remoteAddress, const char* buffer, int length, PNF_UDP_OPTIONS options)
{
	if (id < FirstEndpoint || id >= FirstEndpoint + PacketCount || remoteAddress == NULL || buffer == NULL || length != 1 || options == NULL || options->optionsLength != 0)
		return NF_STATUS_FAIL;

	const auto remote = reinterpret_cast<const SOCKADDR_IN*>(remoteAddress);
	const int index = static_cast<int>(id - FirstEndpoint);
	if (remote->sin_family != AF_INET || remote->sin_addr.s_addr != htonl(0x08080808) || remote->sin_port != htons(9000) || index < 0 || index >= PacketCount)
		return NF_STATUS_FAIL;
	if (static_cast<unsigned char>(buffer[0]) != static_cast<unsigned char>(index))
		return NF_STATUS_FAIL;

	{
		lock_guard<mutex> lock(receiveLock);
		if (!received[index])
		{
			received[index] = true;
			++receiveCount;
		}
	}
	receiveReady.notify_all();
	return NF_STATUS_SUCCESS;
}

int main()
{
	WSADATA wsa{};
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return 1;

	USHORT udpPort = 0;
	USHORT tcpPort = 0;
	const SOCKET udpRelay = CreateLoopbackSocket(SOCK_DGRAM, udpPort);
	const SOCKET tcpServer = CreateLoopbackSocket(SOCK_STREAM, tcpPort);
	if (udpRelay == INVALID_SOCKET || tcpServer == INVALID_SOCKET || listen(tcpServer, PacketCount) == SOCKET_ERROR)
		return 1;

	promise<bool> serverResult;
	auto serverFuture = serverResult.get_future();
	thread server([&]
	{
		bool ok = false;
		vector<SOCKET> clients;
		for (int connection = 0; connection < PacketCount; ++connection)
		{
			const SOCKET client = accept(tcpServer, NULL, NULL);
			if (client == INVALID_SOCKET)
				break;
			array<char, 10> request{};
			const char hello[] = { 0x05, 0x00 };
			const char associateResponse[] = {
				0x05, 0x00, 0x00, 0x01,
				0x7f, 0x00, 0x00, 0x01,
				static_cast<char>((ntohs(udpPort) >> 8) & 0xff),
				static_cast<char>(ntohs(udpPort) & 0xff)
			};

			if (ReceiveExact(client, request.data(), 4) && send(client, hello, sizeof(hello), 0) == sizeof(hello) &&
				ReceiveExact(client, request.data(), 10))
			{
				// This delay proves that udpSend only enqueues work; it must not wait
				// for the SOCKS TCP association on the NetFilter callback thread.
				if (connection == 0)
					this_thread::sleep_for(chrono::milliseconds(400));
				if (send(client, associateResponse, sizeof(associateResponse), 0) == sizeof(associateResponse))
					clients.push_back(client);
			}
			if (clients.empty() || clients.back() != client)
				closesocket(client);
		}
		if (clients.size() == PacketCount)
		{
			for (int i = 0; i < PacketCount; ++i)
			{
				array<char, 64> packet{};
				SOCKADDR_IN peer{};
				int peerLength = sizeof(peer);
				const int length = recvfrom(udpRelay, packet.data(), static_cast<int>(packet.size()), 0,
					reinterpret_cast<PSOCKADDR>(&peer), &peerLength);
				if (length != 11 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != 1 ||
					static_cast<unsigned char>(packet[10]) >= PacketCount || !SendUdpReply(udpRelay, peer, peerLength, packet[10]))
					break;
				ok = i + 1 == PacketCount;
			}
			if (ok)
				this_thread::sleep_for(chrono::seconds(1));
		}
		for (const SOCKET client : clients)
			closesocket(client);
		serverResult.set_value(ok);
	});

	filterParent = false;
	filterTCP = false;
	filterUDP = true;
	filterDNS = false;
	dnsOnly = false;
	tgtHost = L"127.0.0.1";
	tgtPort = to_wstring(ntohs(tcpPort));
	tgtUsername.clear();
	tgtPassword.clear();
	bypassList.clear();
	handleList = { wregex(L"Idle") };

	bool passed = eh_init();
	NF_UDP_CONN_INFO info{};
	info.processId = 0;
	info.ip_family = AF_INET;

	SOCKADDR_IN target{};
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = htonl(0x08080808);
	target.sin_port = htons(9000);
	NF_UDP_OPTIONS options{};
	options.optionsLength = 0;

	const auto callbackStart = chrono::steady_clock::now();
	for (int i = 0; i < PacketCount; ++i)
	{
		udpCreated(FirstEndpoint + i, &info);
		const char payload = static_cast<char>(i);
		udpSend(FirstEndpoint + i, reinterpret_cast<const unsigned char*>(&target), &payload, 1, &options);
	}
	const auto callbackElapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - callbackStart);

	passed = passed && callbackElapsed < chrono::milliseconds(100) && WaitForReceives();
	// Leave all receive operations outstanding and let global shutdown cancel
	// them.  This covers unload with many live UDP endpoints, not just the
	// normal per-endpoint udpClosed path.
	eh_free();
	server.join();
	closesocket(tcpServer);
	closesocket(udpRelay);
	WSACleanup();

	passed = passed && serverFuture.get() && receiveCount == PacketCount;
	printf("UDP IOCP receive regression: %s (%d ms callback, %d/%d replies across %d endpoints)\n", passed ? "PASS" : "FAIL", static_cast<int>(callbackElapsed.count()), receiveCount, PacketCount, PacketCount);
	return passed ? 0 : 1;
}
