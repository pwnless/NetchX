#include "../SocksHelper.h"

#include <array>
#include <future>

wstring tgtHost;
wstring tgtPort;
string tgtUsername;
string tgtPassword;

namespace
{
	enum class RelayAddressType
	{
		IPv4,
		Domain,
		UnspecifiedIPv4
	};

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
		if (type == SOCK_STREAM && listen(socket, 1) == SOCKET_ERROR)
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

		DWORD timeout = 15000;
		setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
		port = ntohs(address.sin_port);
		return socket;
	}

	vector<char> MakeAssociateResponse(RelayAddressType type, USHORT relayPort)
	{
		switch (type)
		{
		case RelayAddressType::IPv4:
			return {
				0x05, 0x00, 0x00, 0x01,
				0x7f, 0x00, 0x00, 0x01,
				static_cast<char>((relayPort >> 8) & 0xff), static_cast<char>(relayPort & 0xff)
			};
		case RelayAddressType::Domain:
		{
			const string domain = "127.0.0.1";
			vector<char> response = { 0x05, 0x00, 0x00, 0x03, static_cast<char>(domain.size()) };
			response.insert(response.end(), domain.begin(), domain.end());
			response.push_back(static_cast<char>((relayPort >> 8) & 0xff));
			response.push_back(static_cast<char>(relayPort & 0xff));
			return response;
		}
		case RelayAddressType::UnspecifiedIPv4:
			return {
				0x05, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				static_cast<char>((relayPort >> 8) & 0xff), static_cast<char>(relayPort & 0xff)
			};
		}
		return {};
	}

	bool IsExpectedUdpPacket(const char* packet, int length, char sequence)
	{
		return length == 11 && packet[0] == 0 && packet[1] == 0 && packet[2] == 0 && packet[3] == 0x01 &&
			static_cast<unsigned char>(packet[4]) == 8 && static_cast<unsigned char>(packet[5]) == 8 &&
			static_cast<unsigned char>(packet[6]) == 8 && static_cast<unsigned char>(packet[7]) == 8 &&
			static_cast<unsigned char>(packet[8]) == 0 && static_cast<unsigned char>(packet[9]) == 53 &&
			packet[10] == sequence;
	}

	bool RunAssociationCase(RelayAddressType type, bool testIdleControlChannel)
	{
		USHORT relayPort = 0;
		USHORT socksPort = 0;
		const SOCKET relay = CreateLoopbackSocket(SOCK_DGRAM, relayPort);
		const SOCKET listener = CreateLoopbackSocket(SOCK_STREAM, socksPort);
		if (relay == INVALID_SOCKET || listener == INVALID_SOCKET)
		{
			if (relay != INVALID_SOCKET)
				closesocket(relay);
			if (listener != INVALID_SOCKET)
				closesocket(listener);
			return false;
		}

		const int packetCount = testIdleControlChannel ? 2 : 1;
		promise<bool> serverResult;
		auto serverFuture = serverResult.get_future();
		thread server([&]
		{
			bool ok = false;
			const SOCKET client = accept(listener, NULL, NULL);
			if (client != INVALID_SOCKET)
			{
				char hello[4]{};
				char associate[10]{};
				const char selectedAuthentication[] = { 0x05, 0x00 };
				const vector<char> associateResponse = MakeAssociateResponse(type, relayPort);
				ok = ReceiveExact(client, hello, sizeof(hello)) && hello[0] == 0x05 && hello[1] == 0x02 &&
					SendExact(client, selectedAuthentication, sizeof(selectedAuthentication)) &&
					ReceiveExact(client, associate, sizeof(associate)) && associate[0] == 0x05 && associate[1] == 0x03 && associate[3] == 0x01 &&
					SendExact(client, associateResponse.data(), static_cast<int>(associateResponse.size()));

				for (int packetIndex = 0; ok && packetIndex < packetCount; ++packetIndex)
				{
					array<char, 64> packet{};
					SOCKADDR_IN peer{};
					int peerLength = sizeof(peer);
					const int received = recvfrom(relay, packet.data(), static_cast<int>(packet.size()), 0,
						reinterpret_cast<PSOCKADDR>(&peer), &peerLength);
					const char sequence = packetIndex == 0 ? 'a' : 'b';
					ok = IsExpectedUdpPacket(packet.data(), received, sequence) &&
						sendto(relay, packet.data(), received, 0, reinterpret_cast<PSOCKADDR>(&peer), peerLength) == received;
				}

				// Let the client close the TCP control connection after its final UDP reply.
				if (ok)
				{
					char unused = 0;
					recv(client, &unused, sizeof(unused), 0);
				}
				closesocket(client);
			}
			serverResult.set_value(ok);
		});

		tgtHost = L"127.0.0.1";
		tgtPort = to_wstring(socksPort);
		tgtUsername.clear();
		tgtPassword.clear();

		SocksHelper::UDP remote;
		SOCKADDR_IN target{};
		target.sin_family = AF_INET;
		target.sin_addr.s_addr = htonl(0x08080808);
		target.sin_port = htons(53);
		char response[16]{};
		SOCKADDR_IN6 responseAddress{};
		timeval timeout{};
		timeout.tv_sec = 3;

		bool ok = remote.EnsureReady();
		ok = ok && remote.Send(reinterpret_cast<PSOCKADDR_IN6>(&target), "a", 1) == 1;
		ok = ok && remote.Read(&responseAddress, response, sizeof(response), &timeout) == 1 && response[0] == 'a';
		if (testIdleControlChannel)
		{
			// The SOCKS setup uses a five-second timeout. A healthy UDP association
			// must remain usable after the TCP control connection is idle longer than that.
			this_thread::sleep_for(chrono::milliseconds(5500));
			memset(response, 0, sizeof(response));
			ok = ok && remote.Send(reinterpret_cast<PSOCKADDR_IN6>(&target), "b", 1) == 1;
			ok = ok && remote.Read(&responseAddress, response, sizeof(response), &timeout) == 1 && response[0] == 'b';
		}
		remote.Stop();

		server.join();
		closesocket(listener);
		closesocket(relay);
		return ok && serverFuture.get();
	}

	bool RejectsOversizedSocksUdpDatagram()
	{
		USHORT relayPort = 0;
		USHORT socksPort = 0;
		const SOCKET relay = CreateLoopbackSocket(SOCK_DGRAM, relayPort);
		const SOCKET listener = CreateLoopbackSocket(SOCK_STREAM, socksPort);
		if (relay == INVALID_SOCKET || listener == INVALID_SOCKET)
		{
			if (relay != INVALID_SOCKET)
				closesocket(relay);
			if (listener != INVALID_SOCKET)
				closesocket(listener);
			return false;
		}

		promise<bool> serverResult;
		auto serverFuture = serverResult.get_future();
		thread server([&]
		{
			bool ok = false;
			const SOCKET client = accept(listener, NULL, NULL);
			if (client != INVALID_SOCKET)
			{
				char hello[4]{};
				char associate[10]{};
				const char selectedAuthentication[] = { 0x05, 0x00 };
				const vector<char> associateResponse = MakeAssociateResponse(RelayAddressType::IPv4, relayPort);
				ok = ReceiveExact(client, hello, sizeof(hello)) && SendExact(client, selectedAuthentication, sizeof(selectedAuthentication)) &&
					ReceiveExact(client, associate, sizeof(associate)) && SendExact(client, associateResponse.data(), static_cast<int>(associateResponse.size()));
				char unused = 0;
				recv(client, &unused, sizeof(unused), 0);
				closesocket(client);
			}
			serverResult.set_value(ok);
		});

		tgtHost = L"127.0.0.1";
		tgtPort = to_wstring(socksPort);
		tgtUsername.clear();
		tgtPassword.clear();

		SocksHelper::UDP remote;
		SOCKADDR_IN target{};
		target.sin_family = AF_INET;
		target.sin_addr.s_addr = htonl(0x08080808);
		target.sin_port = htons(53);
		vector<char> oversized(65507 - 10 + 1);

		const bool ready = remote.EnsureReady();
		WSASetLastError(0);
		const int result = ready ? remote.Send(reinterpret_cast<PSOCKADDR_IN6>(&target), oversized.data(), static_cast<int>(oversized.size())) : SOCKET_ERROR;
		const int error = WSAGetLastError();
		remote.Stop();

		server.join();
		closesocket(listener);
		closesocket(relay);
		return ready && result == SOCKET_ERROR && error == WSAEMSGSIZE && serverFuture.get();
	}
}

int main()
{
	WSADATA data{};
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
		return 1;

	const bool idle = RunAssociationCase(RelayAddressType::IPv4, true);
	const bool domain = RunAssociationCase(RelayAddressType::Domain, false);
	const bool wildcard = RunAssociationCase(RelayAddressType::UnspecifiedIPv4, false);
	const bool oversized = RejectsOversizedSocksUdpDatagram();
	WSACleanup();

	const bool passed = idle && domain && wildcard && oversized;
	printf("SOCKS UDP association lifecycle regression: %s (idle=%s, domain=%s, wildcard=%s, oversized=%s)\n",
		passed ? "PASS" : "FAIL", idle ? "PASS" : "FAIL", domain ? "PASS" : "FAIL",
		wildcard ? "PASS" : "FAIL", oversized ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}