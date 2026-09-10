#include "../SocksHelper.h"

#include <array>
#include <future>

wstring tgtHost;
wstring tgtPort;
string tgtUsername;
string tgtPassword;

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

	bool SendOneByteAtATime(SOCKET socket, const char* buffer, int length)
	{
		for (int sent = 0; sent < length; ++sent)
			if (send(socket, buffer + sent, 1, 0) != 1)
				return false;
		return true;
	}

	SOCKET CreateLoopbackSocket(int type, USHORT& port)
	{
		SOCKET socket = ::socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
		if (socket == INVALID_SOCKET)
			return INVALID_SOCKET;

		SOCKADDR_IN address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (::bind(socket, (PSOCKADDR)&address, sizeof(address)) == SOCKET_ERROR)
		{
			closesocket(socket);
			return INVALID_SOCKET;
		}

		int length = sizeof(address);
		if (getsockname(socket, (PSOCKADDR)&address, &length) == SOCKET_ERROR)
		{
			closesocket(socket);
			return INVALID_SOCKET;
		}
		port = address.sin_port;
		return socket;
	}

	bool RunUdpParserRegression()
	{
		USHORT udpPort = 0;
		const SOCKET udpRelay = CreateLoopbackSocket(SOCK_DGRAM, udpPort);
		USHORT tcpPort = 0;
		const SOCKET tcpServer = CreateLoopbackSocket(SOCK_STREAM, tcpPort);
		if (udpRelay == INVALID_SOCKET || tcpServer == INVALID_SOCKET || listen(tcpServer, 1) == SOCKET_ERROR)
			return false;

		tgtHost = L"127.0.0.1";
		tgtPort = to_wstring(ntohs(tcpPort));
		tgtUsername.clear();
		tgtPassword.clear();

		promise<bool> serverResult;
		auto serverFuture = serverResult.get_future();
		thread server([&]
		{
			bool ok = false;
			SOCKET client = accept(tcpServer, nullptr, nullptr);
			if (client != INVALID_SOCKET)
			{
				array<char, 10> request{};
				const char hello[] = { 0x05, 0x00 };
				const char associateResponse[] = {
					0x05, 0x00, 0x00, 0x01,
					0x7f, 0x00, 0x00, 0x01,
					static_cast<char>((ntohs(udpPort) >> 8) & 0xff),
					static_cast<char>(ntohs(udpPort) & 0xff)
				};

				if (ReceiveExact(client, request.data(), 4) &&
					SendOneByteAtATime(client, hello, sizeof(hello)) &&
					ReceiveExact(client, request.data(), 10) &&
					SendOneByteAtATime(client, associateResponse, sizeof(associateResponse)))
				{
					array<char, 64> inbound{};
					SOCKADDR_IN clientAddress{};
					int clientAddressLength = sizeof(clientAddress);
					if (recvfrom(udpRelay, inbound.data(), static_cast<int>(inbound.size()), 0,
						(PSOCKADDR)&clientAddress, &clientAddressLength) > 0)
					{
						const char shortPacket[] = { 0x00, 0x00, 0x00, 0x01 };
						const char validPacket[] = {
							0x00, 0x00, 0x00, 0x01,
							0x08, 0x08, 0x08, 0x08,
							0x00, 0x35,
							'o', 'k'
						};
						ok = sendto(udpRelay, shortPacket, sizeof(shortPacket), 0,
							(PSOCKADDR)&clientAddress, clientAddressLength) == sizeof(shortPacket);
						this_thread::sleep_for(chrono::milliseconds(50));
						ok = ok && sendto(udpRelay, validPacket, sizeof(validPacket), 0,
							(PSOCKADDR)&clientAddress, clientAddressLength) == sizeof(validPacket);
					}
				}
				closesocket(client);
			}
			serverResult.set_value(ok);
		});

		SocksHelper::UDP remote;
		SOCKADDR_IN target{};
		target.sin_family = AF_INET;
		target.sin_addr.s_addr = htonl(0x08080808);
		target.sin_port = htons(53);
		char response[16]{};
		SOCKADDR_IN6 responseAddress{};
		timeval timeout{};
		timeout.tv_sec = 3;

		const bool ready = remote.EnsureReady();
		const bool sent = ready && remote.Send((PSOCKADDR_IN6)&target, "x", 1) == 1;
		const int shortResult = sent ? remote.Read(&responseAddress, response, sizeof(response), &timeout) : SOCKET_ERROR;
		const int validResult = sent ? remote.Read(&responseAddress, response, sizeof(response), &timeout) : SOCKET_ERROR;
		remote.Stop();
		server.join();
		closesocket(tcpServer);
		closesocket(udpRelay);

		return serverFuture.get() && shortResult == SOCKET_ERROR && validResult == 2 &&
			response[0] == 'o' && response[1] == 'k' &&
			((PSOCKADDR_IN)&responseAddress)->sin_addr.s_addr == htonl(0x08080808) &&
			((PSOCKADDR_IN)&responseAddress)->sin_port == htons(53);
	}

	bool RejectsOversizedSocksCredentials()
	{
		tgtUsername.assign(256, 'u');
		tgtPassword.clear();
		const bool rejectedUsername = !SocksHelper::Handshake(INVALID_SOCKET);

		tgtUsername.clear();
		tgtPassword.assign(256, 'p');
		const bool rejectedPassword = !SocksHelper::Handshake(INVALID_SOCKET);
		tgtPassword.clear();

		return rejectedUsername && rejectedPassword;
	}
}

int main()
{
	WSADATA data{};
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
		return 1;

	const bool passed = RunUdpParserRegression() && RejectsOversizedSocksCredentials();
	WSACleanup();
	printf("SocksHelper UDP parser and credential bounds regression: %s\n", passed ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}
