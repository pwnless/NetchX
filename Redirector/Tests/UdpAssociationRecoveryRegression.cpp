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
	constexpr ENDPOINT_ID Endpoint = 8765;
	mutex receiveLock;
	condition_variable receiveReady;
	bool receivedFirst = false;
	bool receivedSecond = false;

	bool ReceiveExact(SOCKET socket, char* buffer, int length)
	{
		for (int received = 0; received < length;)
		{
			const int result = recv(socket, buffer + received, length - received, 0);
			if (result <= 0)
				return false;
			received += result;
		}
		return true;
	}

	bool SendExact(SOCKET socket, const char* buffer, int length)
	{
		for (int sent = 0; sent < length;)
		{
			const int result = send(socket, buffer + sent, length - sent, 0);
			if (result <= 0)
				return false;
			sent += result;
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
		if (type == SOCK_STREAM && listen(socket, 2) == SOCKET_ERROR)
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
		port = ntohs(address.sin_port);
		return socket;
	}

	SOCKET AcceptWithTimeout(SOCKET listener, atomic_bool& stop)
	{
		const auto deadline = chrono::steady_clock::now() + chrono::seconds(8);
		while (!stop && chrono::steady_clock::now() < deadline)
		{
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(listener, &fds);
			timeval timeout{};
			timeout.tv_usec = 100000;
			const int ready = select(0, &fds, NULL, NULL, &timeout);
			if (ready > 0)
				return accept(listener, NULL, NULL);
			if (ready == SOCKET_ERROR)
				return INVALID_SOCKET;
		}
		return INVALID_SOCKET;
	}

	bool PerformUdpAssociate(SOCKET client, USHORT relayPort)
	{
		char hello[4]{};
		char associate[10]{};
		const char selectedAuthentication[] = { 0x05, 0x00 };
		const char response[] = {
			0x05, 0x00, 0x00, 0x01,
			0x7f, 0x00, 0x00, 0x01,
			static_cast<char>((relayPort >> 8) & 0xff), static_cast<char>(relayPort & 0xff)
		};
		return ReceiveExact(client, hello, sizeof(hello)) && hello[0] == 0x05 && hello[1] == 0x02 &&
			SendExact(client, selectedAuthentication, sizeof(selectedAuthentication)) &&
			ReceiveExact(client, associate, sizeof(associate)) && associate[0] == 0x05 && associate[1] == 0x03 && associate[3] == 0x01 &&
			SendExact(client, response, sizeof(response));
	}

	bool RelayOnePacket(SOCKET relay, char sequence)
	{
		const auto deadline = chrono::steady_clock::now() + chrono::seconds(6);
		while (chrono::steady_clock::now() < deadline)
		{
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(relay, &fds);
			timeval timeout{};
			timeout.tv_usec = 100000;
			const int ready = select(0, &fds, NULL, NULL, &timeout);
			if (ready == SOCKET_ERROR)
				return false;
			if (ready == 0)
				continue;

			array<char, 64> packet{};
			SOCKADDR_IN peer{};
			int peerLength = sizeof(peer);
			const int received = recvfrom(relay, packet.data(), static_cast<int>(packet.size()), 0,
				reinterpret_cast<PSOCKADDR>(&peer), &peerLength);
			if (received != 11 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0x01 ||
				static_cast<unsigned char>(packet[4]) != 8 || static_cast<unsigned char>(packet[5]) != 8 ||
				static_cast<unsigned char>(packet[6]) != 8 || static_cast<unsigned char>(packet[7]) != 8 ||
				packet[8] != 0x23 || packet[9] != 0x28 || packet[10] != sequence)
				return false;
			return sendto(relay, packet.data(), received, 0, reinterpret_cast<PSOCKADDR>(&peer), peerLength) == received;
		}
		return false;
	}

	bool WaitFor(bool& received, chrono::milliseconds timeout)
	{
		unique_lock<mutex> lock(receiveLock);
		return receiveReady.wait_for(lock, timeout, [&received] { return received; });
	}
}

extern "C" NF_STATUS __cdecl nf_udpPostReceive(ENDPOINT_ID id, const unsigned char* remoteAddress, const char* buffer, int length, PNF_UDP_OPTIONS options)
{
	if (id != Endpoint || remoteAddress == NULL || buffer == NULL || length != 1 || options == NULL || options->optionsLength != 0)
		return NF_STATUS_FAIL;

	const auto remote = reinterpret_cast<const SOCKADDR_IN*>(remoteAddress);
	if (remote->sin_family != AF_INET || remote->sin_addr.s_addr != htonl(0x08080808) || remote->sin_port != htons(9000))
		return NF_STATUS_FAIL;

	{
		lock_guard<mutex> lock(receiveLock);
		if (buffer[0] == 'a')
			receivedFirst = true;
		else if (buffer[0] == 'b')
			receivedSecond = true;
		else
			return NF_STATUS_FAIL;
	}
	receiveReady.notify_all();
	return NF_STATUS_SUCCESS;
}

// EventHandler is normally linked against nfapi.dll. The standalone regression
// supplies the small surface it reaches so it can run without the driver.
extern "C" NF_STATUS __cdecl nf_tcpPostSend(ENDPOINT_ID, const char*, int)
{
	return NF_STATUS_SUCCESS;
}

extern "C" NF_STATUS __cdecl nf_tcpPostReceive(ENDPOINT_ID, const char*, int)
{
	return NF_STATUS_SUCCESS;
}

extern "C" NF_STATUS __cdecl nf_tcpDisableFiltering(ENDPOINT_ID)
{
	return NF_STATUS_SUCCESS;
}

extern "C" NF_STATUS __cdecl nf_udpPostSend(ENDPOINT_ID, const unsigned char*, const char*, int, PNF_UDP_OPTIONS)
{
	return NF_STATUS_SUCCESS;
}

extern "C" NF_STATUS __cdecl nf_udpDisableFiltering(ENDPOINT_ID)
{
	return NF_STATUS_SUCCESS;
}

extern "C" BOOL __cdecl nf_getProcessNameW(DWORD, wchar_t*, DWORD)
{
	return FALSE;
}

extern "C" BOOL __cdecl nf_getProcessNameFromKernel(DWORD, wchar_t*, DWORD)
{
	return FALSE;
}

int main()
{
	WSADATA wsa{};
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return 1;

	USHORT relayPort = 0;
	USHORT socksPort = 0;
	const SOCKET relay = CreateLoopbackSocket(SOCK_DGRAM, relayPort);
	const SOCKET listener = CreateLoopbackSocket(SOCK_STREAM, socksPort);
	if (relay == INVALID_SOCKET || listener == INVALID_SOCKET)
		return 1;

	atomic_bool stopServer = false;
	atomic_bool firstControlClosed = false;
	atomic_bool firstUdpReplySent = false;
	promise<bool> serverResult;
	auto serverFuture = serverResult.get_future();
	thread server([&]
	{
		bool ok = true;
		for (int association = 0; association < 2 && ok; ++association)
		{
			const SOCKET client = AcceptWithTimeout(listener, stopServer);
			if (client == INVALID_SOCKET)
			{
				ok = false;
				break;
			}
			ok = PerformUdpAssociate(client, relayPort) && RelayOnePacket(relay, association == 0 ? 'a' : 'b');
			if (association == 0)
			{
				firstUdpReplySent = true;
				this_thread::sleep_for(chrono::milliseconds(200));
				closesocket(client);
				firstControlClosed = true;
			}
			else
			{
				closesocket(client);
			}
		}
		serverResult.set_value(ok);
	});

	filterParent = false;
	filterTCP = false;
	filterUDP = true;
	filterDNS = false;
	dnsOnly = false;
	tgtHost = L"127.0.0.1";
	tgtPort = to_wstring(socksPort);
	tgtUsername.clear();
	tgtPassword.clear();
	bypassList.clear();
	handleList = { wregex(L"Idle") };

	bool passed = eh_init();
	NF_UDP_CONN_INFO info{};
	info.processId = 0;
	info.ip_family = AF_INET;
	udpCreated(Endpoint, &info);

	SOCKADDR_IN target{};
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = htonl(0x08080808);
	target.sin_port = htons(9000);
	NF_UDP_OPTIONS options{};
	options.optionsLength = 0;

	const char first = 'a';
	udpSend(Endpoint, reinterpret_cast<const unsigned char*>(&target), &first, 1, &options);
	passed = passed && WaitFor(receivedFirst, chrono::seconds(5));
	const auto firstReplyDeadline = chrono::steady_clock::now() + chrono::seconds(2);
	while (passed && !firstUdpReplySent && chrono::steady_clock::now() < firstReplyDeadline)
		this_thread::sleep_for(chrono::milliseconds(10));
	passed = passed && firstUdpReplySent;

	const auto closeDeadline = chrono::steady_clock::now() + chrono::seconds(2);
	while (passed && !firstControlClosed && chrono::steady_clock::now() < closeDeadline)
		this_thread::sleep_for(chrono::milliseconds(10));
	passed = passed && firstControlClosed;
	this_thread::sleep_for(chrono::milliseconds(300));

	const char second = 'b';
	for (int attempt = 0; passed && !receivedSecond && attempt < 12; ++attempt)
	{
		udpSend(Endpoint, reinterpret_cast<const unsigned char*>(&target), &second, 1, &options);
		WaitFor(receivedSecond, chrono::milliseconds(250));
	}
	passed = passed && receivedSecond;

	eh_free();
	stopServer = true;
	server.join();
	closesocket(listener);
	closesocket(relay);
	WSACleanup();

	passed = passed && serverFuture.get();
	printf("UDP SOCKS-association recovery regression: %s\n", passed ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}