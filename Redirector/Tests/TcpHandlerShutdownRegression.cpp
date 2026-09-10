#include "TCPHandler.h"

#include <array>
#include <future>

extern atomic_ushort tcpListen;
extern wstring tgtHost;
extern wstring tgtPort;
extern string tgtUsername;
extern string tgtPassword;

namespace
{
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

	SOCKET CreateLoopbackListener(USHORT& port)
	{
		const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listener == INVALID_SOCKET)
			return INVALID_SOCKET;

		SOCKADDR_IN address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (::bind(listener, reinterpret_cast<PSOCKADDR>(&address), sizeof(address)) == SOCKET_ERROR || listen(listener, 1) == SOCKET_ERROR)
		{
			closesocket(listener);
			return INVALID_SOCKET;
		}

		int length = sizeof(address);
		if (getsockname(listener, reinterpret_cast<PSOCKADDR>(&address), &length) == SOCKET_ERROR)
		{
			closesocket(listener);
			return INVALID_SOCKET;
		}
		port = address.sin_port;
		return listener;
	}
}

int main()
{
	WSADATA wsa{};
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return 1;

	USHORT socksPort = 0;
	const SOCKET socksListener = CreateLoopbackListener(socksPort);
	if (socksListener == INVALID_SOCKET)
		return 1;

	promise<bool> handshake;
	auto handshakeFuture = handshake.get_future();
	promise<void> serverStopped;
	auto serverStoppedFuture = serverStopped.get_future();
	thread socksServer([&]
	{
		bool ok = false;
		const SOCKET client = accept(socksListener, NULL, NULL);
		if (client != INVALID_SOCKET)
		{
			array<char, 10> request{};
			const char hello[] = { 0x05, 0x00 };
			const char response[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			ok = ReceiveExact(client, request.data(), 4) && send(client, hello, sizeof(hello), 0) == sizeof(hello) &&
				ReceiveExact(client, request.data(), 10) && send(client, response, sizeof(response), 0) == sizeof(response);
			handshake.set_value(ok);
			if (ok)
			{
				char buffer[1];
				recv(client, buffer, sizeof(buffer), 0);
			}
			closesocket(client);
		}
		else
		{
			handshake.set_value(false);
		}
		serverStopped.set_value();
	});

	tgtHost = L"127.0.0.1";
	tgtPort = to_wstring(ntohs(socksPort));
	tgtUsername.clear();
	tgtPassword.clear();

	bool passed = TCPHandler::INIT();
	const SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SOCKADDR_IN local{};
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	passed = passed && client != INVALID_SOCKET && ::bind(client, reinterpret_cast<PSOCKADDR>(&local), sizeof(local)) != SOCKET_ERROR;
	int localLength = sizeof(local);
	passed = passed && getsockname(client, reinterpret_cast<PSOCKADDR>(&local), &localLength) != SOCKET_ERROR;

	SOCKADDR_IN6 interceptedClient{};
	auto interceptedClientV4 = reinterpret_cast<PSOCKADDR_IN>(&interceptedClient);
	interceptedClientV4->sin_family = AF_INET;
	interceptedClientV4->sin_port = local.sin_port;
	SOCKADDR_IN6 remote{};
	auto remoteV4 = reinterpret_cast<PSOCKADDR_IN>(&remote);
	remoteV4->sin_family = AF_INET;
	remoteV4->sin_addr.s_addr = htonl(0xc0000201);
	remoteV4->sin_port = htons(9);
	TCPHandler::CreateHandler(interceptedClient, remote);

	SOCKADDR_IN redirector{};
	redirector.sin_family = AF_INET;
	redirector.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	redirector.sin_port = tcpListen.load();
	passed = passed && ::connect(client, reinterpret_cast<PSOCKADDR>(&redirector), sizeof(redirector)) != SOCKET_ERROR;
	passed = passed && handshakeFuture.wait_for(chrono::seconds(3)) == future_status::ready && handshakeFuture.get();

	this_thread::sleep_for(chrono::milliseconds(100));
	const auto stopStarted = chrono::steady_clock::now();
	TCPHandler::FREE();
	const auto stopElapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - stopStarted);
	passed = passed && stopElapsed < chrono::seconds(3) && serverStoppedFuture.wait_for(chrono::seconds(1)) == future_status::ready;

	if (client != INVALID_SOCKET)
		closesocket(client);
	socksServer.join();
	closesocket(socksListener);
	WSACleanup();

	printf("TCP IOCP shutdown regression: %s (%d ms)\n", passed ? "PASS" : "FAIL", static_cast<int>(stopElapsed.count()));
	return passed ? 0 : 1;
}
