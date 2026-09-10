#include "EventHandler.h"

#include "DNSHandler.h"
#include "TCPHandler.h"

#include <deque>

extern bool filterParent;
extern bool filterTCP;
extern bool filterUDP;
extern bool filterDNS;

extern bool dnsOnly;

extern vector<wregex> bypassList;
extern vector<wregex> handleList;
extern shared_mutex ruleLock;
extern atomic_ushort tcpListen;
DWORD CurrentID = 0;

atomic_bool eventStopping = true;
atomic_ullong UP = { 0 };
atomic_ullong DL = { 0 };

namespace
{
	// NetFilter invokes udpSend on a driver callback thread.  Association with a
	// SOCKS server may perform DNS and several blocking TCP reads, so that work
	// must never run on the callback thread.
	constexpr size_t UdpDispatchWorkerCount = 8;
	constexpr size_t MaxManagedUdpContexts = 1024;
	constexpr size_t MaxPendingUdpPacketsPerContext = 64;
	constexpr size_t MaxPendingUdpPackets = 4096;
	constexpr size_t MaxPendingUdpBytes = 16 * 1024 * 1024;
	constexpr size_t MaxUdpPacketBytes = 65507;
	constexpr size_t MaxUdpOptionBytes = 4096;
	constexpr size_t UdpOptionsHeaderLength = offsetof(NF_UDP_OPTIONS, options);
	constexpr size_t MaxUdpReceiveWorkers = 16;

	enum class UdpAssociationState
	{
		New,
		Associating,
		Ready,
		Failed,
		Closed
	};

	struct UdpPacket
	{
		SOCKADDR_IN6 target{};
		vector<char> payload;
		vector<char> options;
	};

	struct UdpContext
	{
		explicit UdpContext(ENDPOINT_ID endpoint) : id(endpoint) {}

		const ENDPOINT_ID id;
		shared_ptr<SocksHelper::UDP> remote = make_shared<SocksHelper::UDP>();
		mutex lock;
		deque<unique_ptr<UdpPacket>> pending;
		UdpAssociationState state = UdpAssociationState::New;
		bool scheduled = false;
		bool processing = false;
		bool closed = false;
	};

	struct UdpReceiveOperation
	{
		explicit UdpReceiveOperation(shared_ptr<UdpContext> value, const vector<char>& valueOptions)
			: context(move(value)), options(valueOptions), buffer(MaxUdpPacketBytes)
		{
			wsabuf.buf = buffer.data();
			wsabuf.len = static_cast<ULONG>(buffer.size());
		}

		OVERLAPPED overlapped{};
		WSABUF wsabuf{};
		shared_ptr<UdpContext> context;
		vector<char> options;
		vector<char> buffer;
	};

	mutex udpContextLock;
	map<ENDPOINT_ID, shared_ptr<UdpContext>> udpContext;

	mutex udpDispatchLock;
	condition_variable udpDispatchReady;
	queue<shared_ptr<UdpContext>> udpDispatchQueue;
	vector<thread> udpDispatchWorkers;
	atomic_bool udpDispatchStopping = true;
	atomic_size_t udpPendingPacketCount = 0;
	atomic_size_t udpPendingByteCount = 0;

	HANDLE udpReceivePort = NULL;
	mutex udpReceiveLock;
	condition_variable udpReceiveDrained;
	map<LPOVERLAPPED, shared_ptr<UdpReceiveOperation>> udpReceiveOperations;
	vector<thread> udpReceiveWorkers;
	atomic_bool udpReceiveStopping = true;

	bool ReserveUdpQueueBudget(size_t bytes)
	{
		if (bytes > MaxUdpPacketBytes || udpPendingPacketCount.fetch_add(1) >= MaxPendingUdpPackets)
		{
			if (bytes <= MaxUdpPacketBytes)
				udpPendingPacketCount.fetch_sub(1);
			return false;
		}

		if (udpPendingByteCount.fetch_add(bytes) + bytes > MaxPendingUdpBytes)
		{
			udpPendingByteCount.fetch_sub(bytes);
			udpPendingPacketCount.fetch_sub(1);
			return false;
		}

		return true;
	}

	void ReleaseUdpQueueBudget(const UdpPacket& packet)
	{
		udpPendingByteCount.fetch_sub(packet.payload.size() + packet.options.size());
		udpPendingPacketCount.fetch_sub(1);
	}

	void ClearPendingUdpPackets(UdpContext& context)
	{
		for (const auto& packet : context.pending)
			ReleaseUdpQueueBudget(*packet);
		context.pending.clear();
	}

	void QueueUdpContext(const shared_ptr<UdpContext>& context)
	{
		{
			lock_guard<mutex> lock(udpDispatchLock);
			if (udpDispatchStopping)
				return;
			udpDispatchQueue.push(context);
		}
		udpDispatchReady.notify_one();
	}

	bool StartUdpReceiver(const shared_ptr<UdpContext>& context, const vector<char>& options);
	bool StartUdpReceiveWorkers();
	void StopUdpReceiveWorkers();

	bool CopyUdpTarget(const unsigned char* source, SOCKADDR_IN6& target)
	{
		if (source == NULL)
			return false;

		memset(&target, 0, sizeof(target));
		const auto address = reinterpret_cast<const SOCKADDR*>(source);
		if (address->sa_family == AF_INET)
		{
			memcpy(&target, source, sizeof(SOCKADDR_IN));
			return true;
		}
		if (address->sa_family == AF_INET6)
		{
			memcpy(&target, source, sizeof(SOCKADDR_IN6));
			return true;
		}
		return false;
	}

	void ProcessUdpContext(const shared_ptr<UdpContext>& context)
	{
		vector<unique_ptr<UdpPacket>> packets;
		{
			lock_guard<mutex> lock(context->lock);
			context->scheduled = false;
			if (context->closed)
			{
				ClearPendingUdpPackets(*context);
				return;
			}
			context->processing = true;
			context->state = UdpAssociationState::Associating;
			packets.reserve(context->pending.size());
			while (!context->pending.empty())
			{
				packets.push_back(move(context->pending.front()));
				context->pending.pop_front();
			}
		}

		const bool ready = context->remote->EnsureReady();
		{
			lock_guard<mutex> lock(context->lock);
			if (context->closed)
			{
				for (const auto& packet : packets)
					ReleaseUdpQueueBudget(*packet);
				ClearPendingUdpPackets(*context);
				context->state = UdpAssociationState::Closed;
				context->processing = false;
				return;
			}
			context->state = ready ? UdpAssociationState::Ready : UdpAssociationState::Failed;
		}

		bool receiverStarted = false;
		for (const auto& packet : packets)
		{
			if (ready)
			{
				if (!receiverStarted && context->remote->TryStartReceiver())
					receiverStarted = StartUdpReceiver(context, packet->options);

				if (context->remote->Send(&packet->target, packet->payload.data(), static_cast<int>(packet->payload.size())) == static_cast<int>(packet->payload.size()))
					UP += packet->payload.size();
			}
			ReleaseUdpQueueBudget(*packet);
		}

		bool reschedule = false;
		{
			lock_guard<mutex> lock(context->lock);
			context->processing = false;
			if (context->closed)
			{
				ClearPendingUdpPackets(*context);
				context->state = UdpAssociationState::Closed;
			}
			else if (!context->pending.empty())
			{
				context->scheduled = true;
				reschedule = true;
			}
		}
		if (reschedule)
			QueueUdpContext(context);
	}

	void UdpDispatchWorker()
	{
		while (true)
		{
			shared_ptr<UdpContext> context;
			{
				unique_lock<mutex> lock(udpDispatchLock);
				udpDispatchReady.wait(lock, [] { return udpDispatchStopping || !udpDispatchQueue.empty(); });
				if (udpDispatchStopping && udpDispatchQueue.empty())
					return;
				context = move(udpDispatchQueue.front());
				udpDispatchQueue.pop();
			}
			ProcessUdpContext(context);
		}
	}

	bool StartUdpDispatchWorkers()
	{
		udpDispatchStopping = false;
		try
		{
			udpDispatchWorkers.reserve(UdpDispatchWorkerCount);
			for (size_t i = 0; i < UdpDispatchWorkerCount; ++i)
				udpDispatchWorkers.emplace_back(UdpDispatchWorker);
		}
		catch (...)
		{
			udpDispatchStopping = true;
			udpDispatchReady.notify_all();
			for (auto& worker : udpDispatchWorkers)
				if (worker.joinable())
					worker.join();
			udpDispatchWorkers.clear();
			return false;
		}
		return true;
	}

	void StopUdpDispatchWorkers()
	{
		udpDispatchStopping = true;
		{
			lock_guard<mutex> lock(udpDispatchLock);
			while (!udpDispatchQueue.empty())
				udpDispatchQueue.pop();
		}
		udpDispatchReady.notify_all();
		for (auto& worker : udpDispatchWorkers)
			if (worker.joinable())
				worker.join();
		udpDispatchWorkers.clear();
		udpPendingPacketCount = 0;
		udpPendingByteCount = 0;
	}

	size_t GetUdpReceiveWorkerCount()
	{
		const unsigned int processors = thread::hardware_concurrency();
		return (std::min)(MaxUdpReceiveWorkers, (std::max)(size_t{ 2 }, static_cast<size_t>(processors == 0 ? 2 : processors * 2)));
	}

	void RetireUdpReceiveOperation(const shared_ptr<UdpReceiveOperation>& operation)
	{
		{
			lock_guard<mutex> lock(udpReceiveLock);
			auto it = udpReceiveOperations.find(&operation->overlapped);
			if (it != udpReceiveOperations.end() && it->second == operation)
				udpReceiveOperations.erase(it);
		}
		operation->context->remote->ResetReceiver();
		udpReceiveDrained.notify_all();
	}

	bool PostUdpReceive(const shared_ptr<UdpReceiveOperation>& operation)
	{
		if (eventStopping || udpReceiveStopping)
			return false;
		{
			lock_guard<mutex> lock(operation->context->lock);
			if (operation->context->closed)
				return false;
		}

		ZeroMemory(&operation->overlapped, sizeof(operation->overlapped));
		operation->wsabuf.buf = operation->buffer.data();
		operation->wsabuf.len = static_cast<ULONG>(operation->buffer.size());
		return operation->context->remote->BeginReceive(&operation->wsabuf, &operation->overlapped);
	}

	void ProcessUdpReceiveCompletion(const shared_ptr<UdpReceiveOperation>& operation, bool completed, DWORD transferred)
	{
		bool keepReceiving = false;
		if (completed && transferred > 0 && !eventStopping)
		{
			{
				lock_guard<mutex> lock(operation->context->lock);
				keepReceiving = !operation->context->closed;
			}
			if (keepReceiving)
			{
				SOCKADDR_IN6 target{};
				const int length = SocksHelper::UDP::DecodePacket(&target, operation->buffer.data(), static_cast<int>(transferred));
				if (length > 0)
				{
					DL += length;
					nf_udpPostReceive(operation->context->id, (PBYTE)&target, operation->buffer.data(), length,
						(PNF_UDP_OPTIONS)operation->options.data());
				}
			}
		}

		if (keepReceiving && PostUdpReceive(operation))
			return;

		RetireUdpReceiveOperation(operation);
	}

	void UdpReceiveWorker()
	{
		while (true)
		{
			DWORD transferred = 0;
			ULONG_PTR completionKey = 0;
			LPOVERLAPPED overlapped = NULL;
			const BOOL completed = GetQueuedCompletionStatus(udpReceivePort, &transferred, &completionKey, &overlapped, INFINITE);
			UNREFERENCED_PARAMETER(completionKey);
			if (overlapped == NULL)
			{
				if (udpReceiveStopping)
					return;
				continue;
			}

			shared_ptr<UdpReceiveOperation> operation;
			{
				lock_guard<mutex> lock(udpReceiveLock);
				auto it = udpReceiveOperations.find(overlapped);
				if (it != udpReceiveOperations.end())
					operation = it->second;
			}
			if (operation)
				ProcessUdpReceiveCompletion(operation, completed == TRUE, transferred);
		}
	}

	bool StartUdpReceiveWorkers()
	{
		udpReceivePort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (udpReceivePort == NULL)
			return false;

		udpReceiveStopping = false;
		try
		{
			udpReceiveWorkers.reserve(GetUdpReceiveWorkerCount());
			for (size_t i = 0; i < GetUdpReceiveWorkerCount(); ++i)
				udpReceiveWorkers.emplace_back(UdpReceiveWorker);
		}
		catch (...)
		{
			udpReceiveStopping = true;
			for (size_t i = 0; i < udpReceiveWorkers.size(); ++i)
				PostQueuedCompletionStatus(udpReceivePort, 0, 0, NULL);
			for (auto& worker : udpReceiveWorkers)
				if (worker.joinable())
					worker.join();
			udpReceiveWorkers.clear();
			CloseHandle(udpReceivePort);
			udpReceivePort = NULL;
			return false;
		}

		return true;
	}

	void StopUdpReceiveWorkers()
	{
		if (udpReceivePort == NULL)
			return;

		udpReceiveStopping = true;
		{
			unique_lock<mutex> lock(udpReceiveLock);
			udpReceiveDrained.wait(lock, [] { return udpReceiveOperations.empty(); });
		}
		for (size_t i = 0; i < udpReceiveWorkers.size(); ++i)
			PostQueuedCompletionStatus(udpReceivePort, 0, 0, NULL);
		for (auto& worker : udpReceiveWorkers)
			if (worker.joinable())
				worker.join();
		udpReceiveWorkers.clear();
		CloseHandle(udpReceivePort);
		udpReceivePort = NULL;
	}
}

#if defined(_DEBUG)
#define EVENT_LOG(message) do { wcout << message << endl; } while (false)
#else
#define EVENT_LOG(message) do { } while (false)
#endif

wstring ConvertIP(PSOCKADDR addr)
{
	WCHAR buffer[MAX_PATH] = L"";
	DWORD bufferLength = MAX_PATH;

	if (addr->sa_family == AF_INET)
	{
		WSAAddressToStringW(addr, sizeof(SOCKADDR_IN), NULL, buffer, &bufferLength);
	}
	else
	{
		WSAAddressToStringW(addr, sizeof(SOCKADDR_IN6), NULL, buffer, &bufferLength);
	}

	return buffer;
}

wstring GetProcessName(DWORD id)
{
	if (id == 0)
	{
		return L"Idle";
	}

	if (id == 4)
	{
		return L"System";
	}

	wchar_t name[MAX_PATH];
	if (!nf_getProcessNameFromKernel(id, name, MAX_PATH))
	{
		if (!nf_getProcessNameW(id, name, MAX_PATH))
		{
			return L"Unknown";
		}
	}

	wchar_t data[MAX_PATH];
	if (GetLongPathNameW(name, data, MAX_PATH))
	{
		return data;
	}

	return name;
}

bool checkBypassName(const wstring& name)
{
	shared_lock<shared_mutex> lock(ruleLock);
	for (const auto& rule : bypassList)
	{
		if (regex_search(name, rule))
		{
			return true;
		}
	}

	return false;
}

bool checkHandleName(DWORD id, const wstring& name)
{
	shared_lock<shared_mutex> lock(ruleLock);
	{
		for (const auto& rule : handleList)
		{
			if (regex_search(name, rule))
			{
				return true;
			}
		}
	}

	if (filterParent)
	{
		PROCESSENTRY32W PE;
		memset(&PE, 0, sizeof(PROCESSENTRY32W));
		PE.dwSize = sizeof(PROCESSENTRY32W);

		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		if (!Process32FirstW(hSnapshot, &PE))
		{
			CloseHandle(hSnapshot);
			return false;
		}

		do {
			if (PE.th32ProcessID == id)
			{
				auto parentName = GetProcessName(PE.th32ParentProcessID);

				for (const auto& rule : handleList)
				{
					if (regex_search(parentName, rule))
					{
						CloseHandle(hSnapshot);
						return true;
					}
				}
			}
		} while (Process32NextW(hSnapshot, &PE));

		CloseHandle(hSnapshot);
	}

	return false;
}

bool eh_init()
{
	eventStopping = false;
	CurrentID = GetCurrentProcessId();

	if (!DNSHandler::INIT())
		return false;

	if (!TCPHandler::INIT())
	{
		DNSHandler::FREE();
		return false;
	}

	if (!StartUdpDispatchWorkers())
	{
		TCPHandler::FREE();
		DNSHandler::FREE();
		return false;
	}
	if (!StartUdpReceiveWorkers())
	{
		StopUdpDispatchWorkers();
		TCPHandler::FREE();
		DNSHandler::FREE();
		return false;
	}

	return true;
}
void eh_free()
{
	eventStopping = true;
	DNSHandler::FREE();
	TCPHandler::FREE();

	vector<shared_ptr<UdpContext>> contexts;
	{
		lock_guard<mutex> lock(udpContextLock);
		for (const auto& item : udpContext)
		{
			lock_guard<mutex> contextLock(item.second->lock);
			item.second->closed = true;
			item.second->state = UdpAssociationState::Closed;
			ClearPendingUdpPackets(*item.second);
			contexts.push_back(item.second);
		}
		udpContext.clear();
	}
	for (const auto& context : contexts)
		context->remote->Stop();

	StopUdpDispatchWorkers();
	StopUdpReceiveWorkers();

	UP = 0;
	DL = 0;
}

void threadStart()
{

}

void threadEnd()
{

}

namespace
{
	bool StartUdpReceiver(const shared_ptr<UdpContext>& context, const vector<char>& options)
	{
		try
		{
			if (eventStopping || udpReceiveStopping || !context->remote->AssociateReceivePort(udpReceivePort))
			{
				context->remote->ResetReceiver();
				return false;
			}

			auto operation = make_shared<UdpReceiveOperation>(context, options);
			{
				lock_guard<mutex> lock(udpReceiveLock);
				if (udpReceiveStopping)
				{
					context->remote->ResetReceiver();
					return false;
				}
				udpReceiveOperations.emplace(&operation->overlapped, operation);
			}
			if (PostUdpReceive(operation))
				return true;

			RetireUdpReceiveOperation(operation);
			return false;
		}
		catch (...)
		{
			context->remote->ResetReceiver();
			return false;
		}
	}
}

void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO info)
{
	if (eventStopping)
	{
		nf_tcpDisableFiltering(id);
		return;
	}

	if (CurrentID == info->processId)
	{
		nf_tcpDisableFiltering(id);
		return;
	}

	if (!filterTCP)
	{
		nf_tcpDisableFiltering(id);

		EVENT_LOG(L"[Redirector][EventHandler][tcpConnectRequest][" << id << L"][" << info->processId << L"][!filterTCP] " << GetProcessName(info->processId));
		return;
	}

	auto processName = GetProcessName(info->processId);
	if (checkBypassName(processName))
	{
		nf_tcpDisableFiltering(id);

		EVENT_LOG(L"[Redirector][EventHandler][tcpConnectRequest][" << id << L"][" << info->processId << L"][checkBypassName] " << processName);
		return;
	}

	if (!checkHandleName(info->processId, processName))
	{
		nf_tcpDisableFiltering(id);

		EVENT_LOG(L"[Redirector][EventHandler][tcpConnectRequest][" << id << L"][" << info->processId << L"][!checkHandleName] " << processName);
		return;
	}

	if (info->ip_family != AF_INET && info->ip_family != AF_INET6)
	{
		nf_tcpDisableFiltering(id);

		EVENT_LOG(L"[Redirector][EventHandler][tcpConnectRequest][" << id << L"][" << info->processId << L"][!IPv4 && !IPv6] " << processName);
		return;
	}

	SOCKADDR_IN6 client;
	memcpy(&client, info->localAddress, sizeof(SOCKADDR_IN6));

	SOCKADDR_IN6 remote;
	memcpy(&remote, info->remoteAddress, sizeof(SOCKADDR_IN6));

	if (info->ip_family == AF_INET)
	{
		auto addr = (PSOCKADDR_IN)info->remoteAddress;
		addr->sin_family = AF_INET;
		addr->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
		addr->sin_port = tcpListen.load();
	}

	if (info->ip_family == AF_INET6)
	{
		auto addr = (PSOCKADDR_IN6)info->remoteAddress;
		IN6ADDR_SETLOOPBACK(addr);
		addr->sin6_port = tcpListen.load();
	}

	TCPHandler::CreateHandler(client, remote);
	EVENT_LOG(L"[Redirector][EventHandler][tcpConnectRequest][" << id << L"][" << info->processId << L"] " << ConvertIP((PSOCKADDR)&client) << L" -> " << ConvertIP((PSOCKADDR)&remote));
}

void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO info)
{
	UNREFERENCED_PARAMETER(id);
	UNREFERENCED_PARAMETER(info);
	EVENT_LOG(L"[Redirector][EventHandler][tcpConnected][" << id << L"][" << info->processId << L"][" << ConvertIP((PSOCKADDR)info->remoteAddress) << L"] " << GetProcessName(info->processId));
}

void tcpCanSend(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void tcpSend(ENDPOINT_ID id, const char* buffer, int length)
{
	UP += length;

	nf_tcpPostSend(id, buffer, length);
}

void tcpCanReceive(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void tcpReceive(ENDPOINT_ID id, const char* buffer, int length)
{
	DL += length;

	nf_tcpPostReceive(id, buffer, length);
}

void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO info)
{
	UNREFERENCED_PARAMETER(id);
	SOCKADDR_IN6 client;
	memcpy(&client, info->localAddress, sizeof(SOCKADDR_IN6));

	TCPHandler::DeleteHandler(client);

	EVENT_LOG(L"[Redirector][EventHandler][tcpClosed][" << id << L"][" << info->processId << L"]");
}

void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO info)
{
	if (eventStopping)
	{
		nf_udpDisableFiltering(id);
		return;
	}

	if (CurrentID == info->processId)
	{
		nf_udpDisableFiltering(id);
		return;
	}

	if (!filterUDP)
	{
		if (!filterDNS) nf_udpDisableFiltering(id);

		EVENT_LOG(L"[Redirector][EventHandler][udpCreated][" << id << L"][" << info->processId << L"][!filterUDP] " << GetProcessName(info->processId));
		return;
	}

	auto processName = GetProcessName(info->processId);
	if (checkBypassName(processName))
	{
		if (dnsOnly) nf_udpDisableFiltering(id);

		EVENT_LOG(L"[Redirector][EventHandler][udpCreated][" << id << L"][" << info->processId << L"][checkBypassName] " << processName);
		return;
	}

	if (!checkHandleName(info->processId, processName))
	{
		if (dnsOnly) nf_udpDisableFiltering(id);

		EVENT_LOG(L"[Redirector][EventHandler][udpCreated][" << id << L"][" << info->processId << L"][!checkHandleName] " << processName);
		return;
	}

	EVENT_LOG(L"[Redirector][EventHandler][udpCreated][" << id << L"][" << info->processId << L"] " << processName);

	bool disableFiltering = false;
	try
	{
		lock_guard<mutex> lock(udpContextLock);
		if (udpContext.find(id) != udpContext.end())
			return;
		if (udpContext.size() >= MaxManagedUdpContexts)
			disableFiltering = true;
		else
			udpContext[id] = make_shared<UdpContext>(id);
	}
	catch (...)
	{
		disableFiltering = true;
	}

	// Prefer a working direct connection over retaining an unbounded number of
	// contexts when the process creates more UDP endpoints than we can service.
	if (disableFiltering)
		nf_udpDisableFiltering(id);
}

void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST info)
{
	UNREFERENCED_PARAMETER(id);
	UNREFERENCED_PARAMETER(info);
}

void udpCanSend(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void udpSend(ENDPOINT_ID id, const unsigned char* target, const char* buffer, int length, PNF_UDP_OPTIONS options)
{
	if (eventStopping)
		return;
	if (target == NULL || buffer == NULL || options == NULL || length < 0)
		return;
	if (DNSHandler::IsDNS((PSOCKADDR_IN6)target))
	{
		if (!filterDNS)
		{
			nf_udpPostSend(id, target, buffer, length, options);

			EVENT_LOG(L"[Redirector][EventHandler][udpSend][" << id << L"] B DNS to " << ConvertIP((PSOCKADDR)target));
			return;
		}
		else
		{
			UP += length;
			DNSHandler::CreateHandler(id, (PSOCKADDR_IN6)target, buffer, length, options);

			EVENT_LOG(L"[Redirector][EventHandler][udpSend][" << id << L"] H DNS to " << ConvertIP((PSOCKADDR)target));
			return;
		}
	}

	if (static_cast<size_t>(length) > MaxUdpPacketBytes || options->optionsLength < 0 ||
		static_cast<size_t>(options->optionsLength) > MaxUdpOptionBytes)
		return;
	SOCKADDR_IN6 copiedTarget{};
	if (!CopyUdpTarget(target, copiedTarget))
		return;

	shared_ptr<UdpContext> context;
	{
		lock_guard<mutex> lock(udpContextLock);
		auto it = udpContext.find(id);
		if (it == udpContext.end())
		{
			nf_udpPostSend(id, target, buffer, length, options);
			return;
		}
		context = it->second;
	}

	const size_t optionsLength = UdpOptionsHeaderLength + static_cast<size_t>(options->optionsLength);
	unique_ptr<UdpPacket> packet;
	try
	{
		packet = make_unique<UdpPacket>(UdpPacket{
			copiedTarget,
			vector<char>(buffer, buffer + length),
			vector<char>(reinterpret_cast<const char*>(options), reinterpret_cast<const char*>(options) + optionsLength)
		});
	}
	catch (...)
	{
		return;
	}

	const size_t queuedBytes = packet->payload.size() + packet->options.size();
	bool schedule = false;
	{
		lock_guard<mutex> lock(context->lock);
		if (context->closed || context->pending.size() >= MaxPendingUdpPacketsPerContext || !ReserveUdpQueueBudget(queuedBytes))
			return;

		context->pending.push_back(move(packet));
		if (!context->scheduled && !context->processing)
		{
			context->scheduled = true;
			schedule = true;
		}
	}
	if (schedule)
		QueueUdpContext(context);
}

void udpCanReceive(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void udpReceive(ENDPOINT_ID id, const unsigned char* target, const char* buffer, int length, PNF_UDP_OPTIONS options)
{
	nf_udpPostReceive(id, target, buffer, length, options);
}

void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO info)
{
	UNREFERENCED_PARAMETER(info);

	EVENT_LOG(L"[Redirector][EventHandler][udpClosed][" << id << L"]");
	shared_ptr<UdpContext> context;
	{
		lock_guard<mutex> lock(udpContextLock);
		auto it = udpContext.find(id);
		if (it != udpContext.end())
		{
			context = it->second;
			udpContext.erase(it);
		}
	}
	if (context)
	{
		shared_ptr<SocksHelper::UDP> remote;
		{
			lock_guard<mutex> lock(context->lock);
			context->closed = true;
			context->state = UdpAssociationState::Closed;
			ClearPendingUdpPackets(*context);
			remote = context->remote;
		}
		remote->Stop();
	}
}
