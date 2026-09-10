#include "DNSHandler.h"

#include "SocksHelper.h"

extern bool filterDNS;
extern bool dnsProx;
extern string dnsHost;
extern USHORT dnsPort;

SOCKADDR_IN6 dnsAddr;
atomic_bool dnsStopping = true;

namespace
{
	constexpr size_t DnsWorkerCount = 16;
	constexpr size_t MaxPendingDnsRequests = 1024;
	constexpr size_t MaxDnsMessageBytes = 65535;
	constexpr auto DnsResponseTimeout = chrono::seconds(4);
	constexpr auto DnsResponsePollInterval = chrono::milliseconds(200);

	struct DnsRequest
	{
		ENDPOINT_ID id;
		SOCKADDR_IN6 target;
		vector<char> packet;
		vector<char> options;
		char originalTransactionId[2]{};
		bool hasTransactionId = false;
	};

	// Each DNS worker processes one request at a time, so it can safely own a
	// direct UDP socket or SOCKS UDP association.  Keeping those transports
	// alive removes a bind/connect/associate round-trip from every DNS packet
	// without sharing a datagram socket across concurrent requests.
	struct DnsWorkerTransport
	{
		SOCKET directSocket = INVALID_SOCKET;
		unique_ptr<SocksHelper::UDP> socksUdp;
		vector<char> responseBuffer = vector<char>(MaxDnsMessageBytes);
		unsigned short nextTransactionId = 0;

		~DnsWorkerTransport()
		{
			ResetDirect();
			ResetRemote();
		}

		void ResetDirect()
		{
			if (directSocket != INVALID_SOCKET)
			{
				closesocket(directSocket);
				directSocket = INVALID_SOCKET;
			}
		}

		void ResetRemote()
		{
			if (socksUdp)
			{
				socksUdp->Stop();
				socksUdp.reset();
			}
		}

		bool EnsureDirect()
		{
			if (directSocket != INVALID_SOCKET)
				return true;

			const int family = dnsAddr.sin6_family;
			directSocket = socket(family, SOCK_DGRAM, IPPROTO_UDP);
			if (directSocket == INVALID_SOCKET)
				return false;

			int bindResult;
			if (family == AF_INET)
			{
				SOCKADDR_IN address{};
				address.sin_family = AF_INET;
				bindResult = bind(directSocket, (PSOCKADDR)&address, sizeof(address));
			}
			else
			{
				SOCKADDR_IN6 address{};
				address.sin6_family = AF_INET6;
				bindResult = bind(directSocket, (PSOCKADDR)&address, sizeof(address));
			}
			const int dnsAddressLength = dnsAddr.sin6_family == AF_INET ? static_cast<int>(sizeof(SOCKADDR_IN)) : static_cast<int>(sizeof(SOCKADDR_IN6));
			if (bindResult == SOCKET_ERROR || connect(directSocket, (PSOCKADDR)&dnsAddr, dnsAddressLength) == SOCKET_ERROR)
			{
				ResetDirect();
				return false;
			}

			return true;
		}

		bool EnsureRemote()
		{
			if (!socksUdp)
				socksUdp = make_unique<SocksHelper::UDP>();
			if (socksUdp->EnsureReady())
				return true;

			ResetRemote();
			return false;
		}
	};

	mutex dnsQueueLock;
	condition_variable dnsQueueReady;
	queue<unique_ptr<DnsRequest>> dnsQueue;
	vector<thread> dnsWorkers;

	void PrepareTransactionId(DnsRequest& request, DnsWorkerTransport& transport)
	{
		if (request.packet.size() < 2)
			return;

		request.hasTransactionId = true;
		request.originalTransactionId[0] = request.packet[0];
		request.originalTransactionId[1] = request.packet[1];
		const unsigned short transactionId = ++transport.nextTransactionId;
		request.packet[0] = static_cast<char>(transactionId >> 8);
		request.packet[1] = static_cast<char>(transactionId & 0xff);
	}

	bool IsExpectedResponse(const DnsRequest& request, const char* buffer, int length)
	{
		return !request.hasTransactionId ||
			(length >= 2 && buffer[0] == request.packet[0] && buffer[1] == request.packet[1]);
	}

	void PostResponse(const DnsRequest& request, char* buffer, int length)
	{
		if (request.hasTransactionId)
		{
			buffer[0] = request.originalTransactionId[0];
			buffer[1] = request.originalTransactionId[1];
		}
		if (!dnsStopping)
			nf_udpPostReceive(request.id, (PBYTE)&request.target, buffer, length, (PNF_UDP_OPTIONS)request.options.data());
	}

	bool WaitForDirectResponse(DnsRequest& request, DnsWorkerTransport& transport)
	{
		const auto deadline = chrono::steady_clock::now() + DnsResponseTimeout;
		while (!dnsStopping && chrono::steady_clock::now() < deadline)
		{
			const auto remaining = chrono::duration_cast<chrono::microseconds>(deadline - chrono::steady_clock::now());
			const auto poll = min(remaining, chrono::duration_cast<chrono::microseconds>(DnsResponsePollInterval));
			timeval timeout{};
			timeout.tv_sec = static_cast<long>(poll.count() / 1000000);
			timeout.tv_usec = static_cast<long>(poll.count() % 1000000);
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(transport.directSocket, &fds);
			const int ready = select(NULL, &fds, NULL, NULL, &timeout);
			if (ready == 0)
				continue;
			if (ready == SOCKET_ERROR)
			{
				transport.ResetDirect();
				return false;
			}

			const int size = recv(transport.directSocket, transport.responseBuffer.data(), static_cast<int>(transport.responseBuffer.size()), 0);
			if (size == SOCKET_ERROR || size == 0)
			{
				transport.ResetDirect();
				return false;
			}
			if (IsExpectedResponse(request, transport.responseBuffer.data(), size))
			{
				PostResponse(request, transport.responseBuffer.data(), size);
				return true;
			}
		}
		return false;
	}

	bool WaitForRemoteResponse(DnsRequest& request, DnsWorkerTransport& transport)
	{
		const auto deadline = chrono::steady_clock::now() + DnsResponseTimeout;
		while (!dnsStopping && chrono::steady_clock::now() < deadline)
		{
			const auto remaining = chrono::duration_cast<chrono::microseconds>(deadline - chrono::steady_clock::now());
			const auto poll = min(remaining, chrono::duration_cast<chrono::microseconds>(DnsResponsePollInterval));
			timeval timeout{};
			timeout.tv_sec = static_cast<long>(poll.count() / 1000000);
			timeout.tv_usec = static_cast<long>(poll.count() % 1000000);
			SOCKADDR_IN6 responseTarget{};
			const int size = transport.socksUdp->Read(&responseTarget, transport.responseBuffer.data(), static_cast<int>(transport.responseBuffer.size()), &timeout);
			if (size == 0)
				continue;
			if (size == SOCKET_ERROR)
			{
				transport.ResetRemote();
				return false;
			}
			if (IsExpectedResponse(request, transport.responseBuffer.data(), size))
			{
				PostResponse(request, transport.responseBuffer.data(), size);
				return true;
			}
		}
		return false;
	}

	void HandleClientDNS(DnsRequest& request, DnsWorkerTransport& transport)
	{
		if (!transport.EnsureDirect())
			return;
		if (send(transport.directSocket, request.packet.data(), static_cast<int>(request.packet.size()), 0) != static_cast<int>(request.packet.size()))
		{
			transport.ResetDirect();
			return;
		}
		WaitForDirectResponse(request, transport);
	}

	void HandleRemoteDNS(DnsRequest& request, DnsWorkerTransport& transport)
	{
		if (!transport.EnsureRemote())
			return;
		if (transport.socksUdp->Send((PSOCKADDR_IN6)&dnsAddr, request.packet.data(), static_cast<int>(request.packet.size())) != static_cast<int>(request.packet.size()))
		{
			transport.ResetRemote();
			return;
		}
		WaitForRemoteResponse(request, transport);
	}

	void DnsWorker()
	{
		DnsWorkerTransport transport;
		while (true)
		{
			unique_ptr<DnsRequest> request;
			{
				unique_lock<mutex> lock(dnsQueueLock);
				dnsQueueReady.wait(lock, [] { return dnsStopping || !dnsQueue.empty(); });
				if (dnsStopping && dnsQueue.empty())
					return;

				request = move(dnsQueue.front());
				dnsQueue.pop();
			}

			if (dnsStopping)
				continue;
			PrepareTransactionId(*request, transport);
			if (dnsProx)
				HandleRemoteDNS(*request, transport);
			else
				HandleClientDNS(*request, transport);
		}
	}
}

bool DNSHandler::INIT()
{
	FREE();
	memset(&dnsAddr, 0, sizeof(dnsAddr));

	if (!filterDNS)
		return true;

	auto ipv4 = (PSOCKADDR_IN)&dnsAddr;
	if (inet_pton(AF_INET, dnsHost.c_str(), &ipv4->sin_addr) == 1)
	{
		ipv4->sin_family = AF_INET;
		ipv4->sin_port = htons(dnsPort);
	}
	else
	{
		auto ipv6 = (PSOCKADDR_IN6)&dnsAddr;
		if (inet_pton(AF_INET6, dnsHost.c_str(), &ipv6->sin6_addr) != 1)
			return false;

		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_port = htons(dnsPort);
	}

	dnsStopping = false;
	try
	{
		dnsWorkers.reserve(DnsWorkerCount);
		for (size_t i = 0; i < DnsWorkerCount; ++i)
			dnsWorkers.emplace_back(DnsWorker);
	}
	catch (...)
	{
		FREE();
		return false;
	}

	return true;
}

void DNSHandler::FREE()
{
	dnsStopping = true;
	{
		lock_guard<mutex> lock(dnsQueueLock);
		while (!dnsQueue.empty())
			dnsQueue.pop();
	}
	dnsQueueReady.notify_all();

	for (auto& worker : dnsWorkers)
	{
		if (worker.joinable())
			worker.join();
	}
	dnsWorkers.clear();
}

bool DNSHandler::IsDNS(PSOCKADDR_IN6 target)
{
	if (target->sin6_family == AF_INET)
		return ((PSOCKADDR_IN)target)->sin_port == htons(53);
	else
		return target->sin6_port == htons(53);
}

void DNSHandler::CreateHandler(ENDPOINT_ID id, PSOCKADDR_IN6 target, const char* packet, int length, PNF_UDP_OPTIONS options)
{
	if (length < 0 || target == NULL || packet == NULL || options == NULL || dnsStopping)
		return;
	if (options->optionsLength < 0)
		return;

	const size_t optionsLength = offsetof(NF_UDP_OPTIONS, options) + static_cast<size_t>(options->optionsLength);
	unique_ptr<DnsRequest> request;
	try
	{
		request = make_unique<DnsRequest>(DnsRequest{
			id,
			*target,
			vector<char>(packet, packet + length),
			vector<char>((char*)options, (char*)options + optionsLength)
		});
	}
	catch (...)
	{
		return;
	}

	{
		lock_guard<mutex> lock(dnsQueueLock);
		if (dnsStopping || dnsQueue.size() >= MaxPendingDnsRequests)
			return;

		dnsQueue.push(move(request));
	}
	dnsQueueReady.notify_one();
}
