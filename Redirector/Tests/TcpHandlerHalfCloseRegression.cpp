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
		port = ntohs(address.sin_port);
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
	{
		WSACleanup();
		return 1;
	}

	promise<bool> serverResult;
	auto serverFuture = serverResult.get_future();
	thread socksServer([&]
	{
		bool ok = false;
		const SOCKET client = accept(socksListener, NULL, NULL);
		if (client != INVALID_SOCKET)
		{
			DWORD timeout = 3000;
			setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
			array<char, 10> request{};
			const char hello[] = { 0x05, 0x00 };
			const char response[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			const char requestPayload[] = "request";
			const char responsePayload[] = "response";
			char receivedPayload[sizeof(requestPayload) - 1]{};

			ok = ReceiveExact(client, request.data(), 4) && SendExact(client, hello, sizeof(hello)) &&
				ReceiveExact(client, request.data(), 10) && SendExact(client, response, sizeof(response)) &&
				ReceiveExact(client, receivedPayload, sizeof(receivedPayload)) &&
				memcmp(receivedPayload, requestPayload, sizeof(receivedPayload)) == 0;
			char eof = 0;
			if (ok)
			{
				ok = recv(client, &eof, sizeof(eof), 0) == 0;
				if (ok)
					ok = SendExact(client, responsePayload, sizeof(responsePayload) - 1) && shutdown(client, SD_SEND) != SOCKET_ERROR;
			}
			closesocket(client);
		}
		serverResult.set_value(ok);
	});

	tgtHost = L"127.0.0.1";
	tgtPort = to_wstring(socksPort);
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
	DWORD timeout = 3000;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

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
	const char requestPayload[] = "request";
	char responsePayload[9]{};
	const bool connected = passed && ::connect(client, reinterpret_cast<PSOCKADDR>(&redirector), sizeof(redirector)) != SOCKET_ERROR;
	const bool sent = connected && SendExact(client, requestPayload, sizeof(requestPayload) - 1);
	const bool clientHalfClosed = sent && shutdown(client, SD_SEND) != SOCKET_ERROR;
	const bool received = clientHalfClosed && ReceiveExact(client, responsePayload, sizeof(responsePayload) - 1);
	const bool validResponse = received && memcmp(responsePayload, "response", sizeof(responsePayload) - 1) == 0;
	const bool serverFinished = serverFuture.wait_for(chrono::seconds(3)) == future_status::ready;
	const bool serverPassed = serverFinished && serverFuture.get();
	passed = passed && connected && sent && clientHalfClosed && validResponse && serverPassed;

	TCPHandler::FREE();
	if (client != INVALID_SOCKET)
		closesocket(client);
	socksServer.join();
	closesocket(socksListener);
	WSACleanup();

	printf("TCP IOCP half-close regression: %s (connect=%s, send=%s, client FIN=%s, response=%s, server=%s)\n", passed ? "PASS" : "FAIL",
		connected ? "PASS" : "FAIL", sent ? "PASS" : "FAIL", clientHalfClosed ? "PASS" : "FAIL",
		validResponse ? "PASS" : "FAIL", serverPassed ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}
