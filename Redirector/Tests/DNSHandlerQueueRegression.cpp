#include "DNSHandler.h"

#include <array>
#include <future>
#include <set>

extern bool filterDNS;
extern bool dnsProx;
extern string dnsHost;
extern USHORT dnsPort;
extern wstring tgtHost;
extern wstring tgtPort;
extern string tgtUsername;
extern string tgtPassword;

namespace
{
	constexpr int RequestCount = 64;
	constexpr size_t MaxWorkerSourcePorts = 16;
	mutex responseLock;
	condition_variable responseReady;
	array<bool, RequestCount> responses{};
	int responseCount = 0;
	atomic_int serverRequestCount = 0;
	mutex sourcePortLock;
	set<USHORT> sourcePorts;
	atomic_int socksAssociations = 0;
	atomic_int remoteUdpRequestCount = 0;
	atomic_bool socksServerHealthy = true;
	atomic_bool remoteUdpHealthy = true;

	bool ReceiveExact(SOCKET socket, char* buffer, int length, SOCKADDR_IN& peer, int& peerLength)
	{
		const int received = recvfrom(socket, buffer, length, 0, (PSOCKADDR)&peer, &peerLength);
		return received == length;
	}

	int CreateLoopbackUdpSocket(USHORT& port)
	{
		const SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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

		int addressLength = sizeof(address);
		if (getsockname(socket, (PSOCKADDR)&address, &addressLength) == SOCKET_ERROR)
		{
			closesocket(socket);
			return INVALID_SOCKET;
		}

		DWORD receiveTimeout = 5000;
		setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&receiveTimeout, sizeof(receiveTimeout));

		port = ntohs(address.sin_port);
		return socket;
	}

	int CreateLoopbackTcpSocket(USHORT& port)
	{
		const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (socket == INVALID_SOCKET)
			return INVALID_SOCKET;

		SOCKADDR_IN address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (::bind(socket, (PSOCKADDR)&address, sizeof(address)) == SOCKET_ERROR || listen(socket, 32) == SOCKET_ERROR)
		{
			closesocket(socket);
			return INVALID_SOCKET;
		}

		int addressLength = sizeof(address);
		if (getsockname(socket, (PSOCKADDR)&address, &addressLength) == SOCKET_ERROR)
		{
			closesocket(socket);
			return INVALID_SOCKET;
		}

		port = ntohs(address.sin_port);
		return socket;
	}

	bool ReceiveTcpExact(SOCKET socket, char* buffer, int length)
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

	bool SendTcpExact(SOCKET socket, const char* buffer, int length)
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

	void ResetResponses()
	{
		lock_guard<mutex> lock(responseLock);
		responses.fill(false);
		responseCount = 0;
	}

	bool WaitForResponses()
	{
		unique_lock<mutex> lock(responseLock);
		return responseReady.wait_for(lock, chrono::seconds(8), [] { return responseCount == RequestCount; });
	}

	bool VerifyRemotePooledTransport()
	{
		ResetResponses();
		socksAssociations = 0;
		remoteUdpRequestCount = 0;
		socksServerHealthy = true;
		remoteUdpHealthy = true;

		USHORT relayPort = 0;
		USHORT socksPort = 0;
		const SOCKET relay = CreateLoopbackUdpSocket(relayPort);
		const SOCKET listener = CreateLoopbackTcpSocket(socksPort);
		if (relay == INVALID_SOCKET || listener == INVALID_SOCKET)
		{
			if (relay != INVALID_SOCKET)
				closesocket(relay);
			if (listener != INVALID_SOCKET)
				closesocket(listener);
			return false;
		}

		u_long nonBlocking = 1;
		if (ioctlsocket(listener, FIONBIO, &nonBlocking) == SOCKET_ERROR)
		{
			closesocket(listener);
			closesocket(relay);
			return false;
		}

		atomic_bool stopSocksServer = false;
		thread socksServer([listener, relayPort, &stopSocksServer]
		{
			vector<SOCKET> clients;
			while (!stopSocksServer)
			{
				SOCKET client = accept(listener, NULL, NULL);
				if (client == INVALID_SOCKET)
				{
					if (WSAGetLastError() == WSAEWOULDBLOCK)
					{
						this_thread::sleep_for(chrono::milliseconds(5));
						continue;
					}
					socksServerHealthy = false;
					break;
				}

				u_long blocking = 0;
				if (ioctlsocket(client, FIONBIO, &blocking) == SOCKET_ERROR)
				{
					socksServerHealthy = false;
					closesocket(client);
					continue;
				}
				DWORD timeout = 2000;
				setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
				char hello[4]{};
				char associate[10]{};
				char response[] = { 0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00 };
				const USHORT networkRelayPort = htons(relayPort);
				memcpy(response + 8, &networkRelayPort, sizeof(networkRelayPort));
				const char selectedAuthentication[] = { 0x05, 0x00 };
				const bool valid = ReceiveTcpExact(client, hello, sizeof(hello)) &&
					hello[0] == 0x05 && hello[1] == 0x02 &&
					SendTcpExact(client, selectedAuthentication, sizeof(selectedAuthentication)) &&
					ReceiveTcpExact(client, associate, sizeof(associate)) &&
					associate[0] == 0x05 && associate[1] == 0x03 && associate[3] == 0x01 &&
					SendTcpExact(client, response, sizeof(response));
				if (!valid)
				{
					socksServerHealthy = false;
					closesocket(client);
					continue;
				}
				clients.push_back(client);
				++socksAssociations;
			}
			for (const SOCKET client : clients)
				closesocket(client);
		});

		thread relayServer([relay, relayPort]
		{
			for (int i = 0; i < RequestCount; ++i)
			{
				char packet[64]{};
				SOCKADDR_IN peer{};
				int peerLength = sizeof(peer);
				const int received = recvfrom(relay, packet, sizeof(packet), 0, (PSOCKADDR)&peer, &peerLength);
				if (received != 14 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0x01 ||
					packet[4] != 0x7f || packet[5] != 0 || packet[6] != 0 || packet[7] != 1 ||
					static_cast<unsigned char>(packet[8]) != static_cast<unsigned char>(relayPort >> 8) ||
					static_cast<unsigned char>(packet[9]) != static_cast<unsigned char>(relayPort & 0xff) ||
					sendto(relay, packet, received, 0, (PSOCKADDR)&peer, peerLength) != received)
				{
					remoteUdpHealthy = false;
					return;
				}
				++remoteUdpRequestCount;
			}
		});

		filterDNS = true;
		dnsProx = true;
		dnsHost = "127.0.0.1";
		dnsPort = relayPort;
		tgtHost = L"127.0.0.1";
		tgtPort = to_wstring(socksPort);
		tgtUsername.clear();
		tgtPassword.clear();
		if (!DNSHandler::INIT())
		{
			stopSocksServer = true;
			socksServer.join();
			relayServer.join();
			closesocket(listener);
			closesocket(relay);
			return false;
		}

		NF_UDP_OPTIONS options{};
		options.optionsLength = 0;
		vector<thread> senders;
		senders.reserve(RequestCount);
		for (int i = 0; i < RequestCount; ++i)
		{
			senders.emplace_back([i, &options]
			{
				SOCKADDR_IN6 target{};
				auto ipv4 = (PSOCKADDR_IN)&target;
				ipv4->sin_family = AF_INET;
				ipv4->sin_port = htons(53);
				const char packet[] = { static_cast<char>(i), static_cast<char>(i >> 8), 0x12, 0x34 };
				DNSHandler::CreateHandler(1000 + i, &target, packet, sizeof(packet), &options);
			});
		}
		for (auto& sender : senders)
			sender.join();

		const bool receivedAll = WaitForResponses();
		DNSHandler::FREE();
		stopSocksServer = true;
		socksServer.join();
		relayServer.join();
		closesocket(listener);
		closesocket(relay);

		return receivedAll && remoteUdpHealthy && socksServerHealthy &&
			remoteUdpRequestCount == RequestCount && socksAssociations > 0 &&
			socksAssociations <= static_cast<int>(MaxWorkerSourcePorts);
	}

	bool VerifyPromptShutdown()
	{
		USHORT serverPort = 0;
		const SOCKET server = CreateLoopbackUdpSocket(serverPort);
		if (server == INVALID_SOCKET)
			return false;

		promise<bool> requestReceived;
		auto received = requestReceived.get_future();
		thread dnsServer([server, &requestReceived]
		{
			char packet[4];
			SOCKADDR_IN peer{};
			int peerLength = sizeof(peer);
			requestReceived.set_value(ReceiveExact(server, packet, sizeof(packet), peer, peerLength));
		});

		filterDNS = true;
		dnsProx = false;
		dnsHost = "127.0.0.1";
		dnsPort = serverPort;
		if (!DNSHandler::INIT())
		{
			dnsServer.join();
			closesocket(server);
			return false;
		}

		NF_UDP_OPTIONS options{};
		options.optionsLength = 0;
		SOCKADDR_IN6 target{};
		auto ipv4 = (PSOCKADDR_IN)&target;
		ipv4->sin_family = AF_INET;
		ipv4->sin_port = htons(53);
		const char packet[] = { 0x5a, 0x3c, 0x12, 0x34 };
		DNSHandler::CreateHandler(2000, &target, packet, sizeof(packet), &options);

		const bool sent = received.wait_for(chrono::seconds(2)) == future_status::ready && received.get();
		const auto started = chrono::steady_clock::now();
		DNSHandler::FREE();
		const auto elapsed = chrono::steady_clock::now() - started;
		dnsServer.join();
		closesocket(server);

		return sent && elapsed < chrono::seconds(1);
	}
}

extern "C" NF_STATUS __cdecl TestUdpPostReceive(ENDPOINT_ID id, const unsigned char*, const char* buffer, int length, PNF_UDP_OPTIONS options)
{
	if (length != 4 || options == NULL || options->optionsLength != 0 || id < 1000 || id >= 1000 + RequestCount)
		return NF_STATUS_FAIL;

	const int index = static_cast<int>(id - 1000);
	if (static_cast<unsigned char>(buffer[0]) != static_cast<unsigned char>(index) ||
		static_cast<unsigned char>(buffer[1]) != static_cast<unsigned char>(index >> 8))
		return NF_STATUS_FAIL;

	{
		lock_guard<mutex> lock(responseLock);
		if (!responses[index])
		{
			responses[index] = true;
			++responseCount;
		}
	}
	responseReady.notify_all();
	return NF_STATUS_SUCCESS;
}

int main()
{
	WSADATA wsa{};
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return 1;

	USHORT serverPort = 0;
	const SOCKET server = CreateLoopbackUdpSocket(serverPort);
	if (server == INVALID_SOCKET)
	{
		WSACleanup();
		return 1;
	}

	thread dnsServer([server]
	{
		for (int i = 0; i < RequestCount; ++i)
		{
			char packet[4];
			SOCKADDR_IN peer{};
			int peerLength = sizeof(peer);
			if (!ReceiveExact(server, packet, sizeof(packet), peer, peerLength) ||
				sendto(server, packet, sizeof(packet), 0, (PSOCKADDR)&peer, peerLength) != sizeof(packet))
				return;
			{
				lock_guard<mutex> lock(sourcePortLock);
				sourcePorts.insert(peer.sin_port);
			}
			++serverRequestCount;
		}
	});

	filterDNS = true;
	dnsProx = false;
	dnsHost = "127.0.0.1";
	dnsPort = serverPort;
	if (!DNSHandler::INIT())
	{
		closesocket(server);
		dnsServer.join();
		WSACleanup();
		return 1;
	}

	NF_UDP_OPTIONS options{};
	options.optionsLength = 0;
	vector<thread> senders;
	senders.reserve(RequestCount);
	for (int i = 0; i < RequestCount; ++i)
	{
		senders.emplace_back([i, &options]
		{
			SOCKADDR_IN6 target{};
			auto ipv4 = (PSOCKADDR_IN)&target;
			ipv4->sin_family = AF_INET;
			ipv4->sin_port = htons(53);

			const char packet[] = { static_cast<char>(i), static_cast<char>(i >> 8), 0x12, 0x34 };
			DNSHandler::CreateHandler(1000 + i, &target, packet, sizeof(packet), &options);
		});
	}
	for (auto& sender : senders)
		sender.join();

	const bool passed = WaitForResponses();
	DNSHandler::FREE();
	dnsServer.join();
	closesocket(server);
	const bool pooledSockets = sourcePorts.size() <= MaxWorkerSourcePorts;
	const bool remotePooledTransport = VerifyRemotePooledTransport();
	const bool promptShutdown = VerifyPromptShutdown();
	WSACleanup();

	const bool succeeded = passed && pooledSockets && remotePooledTransport && promptShutdown;
	printf("DNSHandler pooled transport regression: %s (direct=%d/%d responses, %d/%d requests, %zu source ports; remote SOCKS pool=%s, associations=%d, requests=%d; prompt shutdown=%s)\n",
		succeeded ? "PASS" : "FAIL", responseCount, RequestCount, serverRequestCount.load(), RequestCount, sourcePorts.size(),
		remotePooledTransport ? "PASS" : "FAIL", socksAssociations.load(), remoteUdpRequestCount.load(), promptShutdown ? "PASS" : "FAIL");
	return succeeded ? 0 : 1;
}
