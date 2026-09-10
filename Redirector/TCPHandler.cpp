#include "TCPHandler.h"

#include <array>

SOCKET tcpSocket = INVALID_SOCKET;
atomic_ushort tcpListen = 0;

mutex tcpLock;
map<USHORT, SOCKADDR_IN6> tcpContext;
thread tcpAcceptThread;
atomic_bool tcpStopping = true;

namespace
{
	constexpr int TcpTransferBufferSize = 64 * 1024;
	constexpr size_t MinTcpIoWorkers = 2;
	constexpr size_t MaxTcpIoWorkers = 16;
	constexpr size_t MinTcpSetupWorkers = 2;
	constexpr size_t MaxTcpSetupWorkers = 16;
	constexpr size_t MaxPendingTcpSetups = 1024;

	struct TcpSession;

	enum class TcpIoState
	{
		Receiving,
		Sending
	};

	struct TcpPump
	{
		OVERLAPPED overlapped{};
		WSABUF buffer{};
		array<char, TcpTransferBufferSize> storage{};
		TcpSession* session = nullptr;
		SOCKET source = INVALID_SOCKET;
		SOCKET destination = INVALID_SOCKET;
		TcpIoState state = TcpIoState::Receiving;
		DWORD offset = 0;
		DWORD length = 0;
		atomic_bool finished = false;
	};

	struct TcpSession : enable_shared_from_this<TcpSession>
	{
		atomic<SOCKET> client = INVALID_SOCKET;
		shared_ptr<SocksHelper::TCP> remote;
		TcpPump toRemote;
		TcpPump toClient;
		atomic_bool stopping = false;
		atomic_int activePumps = 2;

		void Stop()
		{
			if (stopping.exchange(true))
				return;

			const SOCKET remoteSocket = remote ? remote->GetSocket() : INVALID_SOCKET;
			const SOCKET clientSocket = client.load();
			if (clientSocket != INVALID_SOCKET)
			{
				CancelIoEx(reinterpret_cast<HANDLE>(clientSocket), NULL);
				shutdown(clientSocket, SD_BOTH);
			}
			if (remoteSocket != INVALID_SOCKET)
				CancelIoEx(reinterpret_cast<HANDLE>(remoteSocket), NULL);
			if (remote)
				remote->Stop();
		}
	};

	mutex tcpSessionLock;
	condition_variable tcpSessionsStopped;
	vector<shared_ptr<TcpSession>> tcpSessions;
	mutex tcpSetupLock;
	condition_variable tcpSetupReady;
	queue<SOCKET> tcpSetupQueue;
	vector<thread> tcpSetupWorkers;
	atomic_bool tcpSetupStopping = true;

	HANDLE tcpCompletionPort = NULL;
	vector<thread> tcpIoWorkers;

	void RemoveSession(const shared_ptr<TcpSession>& session)
	{
		lock_guard<mutex> lock(tcpSessionLock);
		auto it = find(tcpSessions.begin(), tcpSessions.end(), session);
		if (it != tcpSessions.end())
			tcpSessions.erase(it);
		if (tcpSessions.empty())
			tcpSessionsStopped.notify_all();
	}

	void AbortSession(const shared_ptr<TcpSession>& session)
	{
		session->Stop();
		const SOCKET client = session->client.exchange(INVALID_SOCKET);
		if (client != INVALID_SOCKET)
			closesocket(client);
		RemoveSession(session);
	}

	// Both pumps reached a clean receive EOF.  At this point each FIN has
	// already been propagated by FinishPumpAfterReceiveEof, and all payload
	// completions preceding it have completed.  Do not call TcpSession::Stop
	// here: shutdown(SD_BOTH) on the client socket can discard data which was
	// successfully handed to WSASend but has not yet been read by the client.
	void FinishSessionGracefully(const shared_ptr<TcpSession>& session)
	{
		const SOCKET client = session->client.exchange(INVALID_SOCKET);
		if (client != INVALID_SOCKET)
			closesocket(client);
		RemoveSession(session);
	}

	// Transport errors abort the complete session: continuing in one direction
	// after a failed send/receive would leave the two TCP streams inconsistent.
	void AbortPump(TcpPump* pump)
	{
		if (pump == nullptr || pump->finished.exchange(true))
			return;

		auto session = pump->session->shared_from_this();
		session->Stop();
		if (session->activePumps.fetch_sub(1) == 1)
			AbortSession(session);
	}

	// EOF on a receive is different from an I/O error.  TCP permits one side
	// to finish sending while it continues receiving.  Propagate that FIN to
	// the destination stream, keep the opposite pump alive, and release the
	// complete session only after both directions have reached EOF.
	void FinishPumpAfterReceiveEof(TcpPump* pump)
	{
		if (pump == nullptr || pump->finished.exchange(true))
			return;

		auto session = pump->session->shared_from_this();
		bool abort = false;
		if (!session->stopping && pump->destination != INVALID_SOCKET &&
			shutdown(pump->destination, SD_SEND) == SOCKET_ERROR)
		{
			// A FIN that cannot be propagated leaves the two streams in
			// different states.  Cancel the opposite outstanding receive rather
			// than leaving this session alive indefinitely.
			session->Stop();
			abort = true;
		}
		if (session->activePumps.fetch_sub(1) == 1)
		{
			if (abort || session->stopping)
				AbortSession(session);
			else
				FinishSessionGracefully(session);
		}
	}

	void PostReceive(TcpPump* pump);
	void PostSend(TcpPump* pump);

	void PostReceive(TcpPump* pump)
	{
		if (pump->finished || pump->session->stopping)
		{
			AbortPump(pump);
			return;
		}

		ZeroMemory(&pump->overlapped, sizeof(pump->overlapped));
		pump->state = TcpIoState::Receiving;
		pump->buffer.buf = pump->storage.data();
		pump->buffer.len = static_cast<ULONG>(pump->storage.size());
		DWORD bytes = 0;
		DWORD flags = 0;
		const int result = WSARecv(pump->source, &pump->buffer, 1, &bytes, &flags, &pump->overlapped, NULL);
		if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
			AbortPump(pump);
	}

	void PostSend(TcpPump* pump)
	{
		if (pump->finished || pump->session->stopping || pump->offset >= pump->length)
		{
			AbortPump(pump);
			return;
		}

		ZeroMemory(&pump->overlapped, sizeof(pump->overlapped));
		pump->state = TcpIoState::Sending;
		pump->buffer.buf = pump->storage.data() + pump->offset;
		pump->buffer.len = pump->length - pump->offset;
		DWORD bytes = 0;
		const int result = WSASend(pump->destination, &pump->buffer, 1, &bytes, 0, &pump->overlapped, NULL);
		if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
			AbortPump(pump);
	}

	void ProcessCompletion(TcpPump* pump, BOOL success, DWORD transferred)
	{
		if (pump == nullptr || pump->finished)
			return;
		if (!success)
		{
			AbortPump(pump);
			return;
		}
		if (transferred == 0)
		{
			if (pump->state == TcpIoState::Receiving)
				FinishPumpAfterReceiveEof(pump);
			else
				AbortPump(pump);
			return;
		}

		if (pump->state == TcpIoState::Receiving)
		{
			if (transferred > pump->storage.size())
			{
				AbortPump(pump);
				return;
			}
			pump->offset = 0;
			pump->length = transferred;
			PostSend(pump);
			return;
		}

		if (transferred > pump->length - pump->offset)
		{
			AbortPump(pump);
			return;
		}
		pump->offset += transferred;
		if (pump->offset == pump->length)
			PostReceive(pump);
		else
			PostSend(pump);
	}

	void IoWorker()
	{
		while (true)
		{
			DWORD transferred = 0;
			ULONG_PTR key = 0;
			LPOVERLAPPED overlapped = NULL;
			const BOOL success = GetQueuedCompletionStatus(tcpCompletionPort, &transferred, &key, &overlapped, INFINITE);
			UNREFERENCED_PARAMETER(key);
			if (overlapped == NULL)
				return;

			auto pump = CONTAINING_RECORD(overlapped, TcpPump, overlapped);
			ProcessCompletion(pump, success, transferred);
		}
	}

	bool StartIoWorkers()
	{
		tcpCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (tcpCompletionPort == NULL)
			return false;

		const DWORD processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
		const size_t workerCount = min(MaxTcpIoWorkers, max(MinTcpIoWorkers, static_cast<size_t>(processors) * 2));
		try
		{
			tcpIoWorkers.reserve(workerCount);
			for (size_t i = 0; i < workerCount; ++i)
				tcpIoWorkers.emplace_back(IoWorker);
		}
		catch (...)
		{
			for (size_t i = 0; i < tcpIoWorkers.size(); ++i)
				PostQueuedCompletionStatus(tcpCompletionPort, 0, 0, NULL);
			for (auto& worker : tcpIoWorkers)
				if (worker.joinable())
					worker.join();
			tcpIoWorkers.clear();
			CloseHandle(tcpCompletionPort);
			tcpCompletionPort = NULL;
			return false;
		}
		return true;
	}

	void StopIoWorkers()
	{
		if (tcpCompletionPort == NULL)
			return;
		for (size_t i = 0; i < tcpIoWorkers.size(); ++i)
			PostQueuedCompletionStatus(tcpCompletionPort, 0, 0, NULL);
		for (auto& worker : tcpIoWorkers)
			if (worker.joinable())
				worker.join();
		tcpIoWorkers.clear();
		CloseHandle(tcpCompletionPort);
		tcpCompletionPort = NULL;
	}

	void TcpSetupWorker()
	{
		while (true)
		{
			SOCKET client = INVALID_SOCKET;
			{
				unique_lock<mutex> lock(tcpSetupLock);
				tcpSetupReady.wait(lock, [] { return tcpSetupStopping || !tcpSetupQueue.empty(); });
				if (tcpSetupStopping && tcpSetupQueue.empty())
					return;
				client = tcpSetupQueue.front();
				tcpSetupQueue.pop();
			}

			try
			{
				TCPHandler::Handle(client);
			}
			catch (...)
			{
				printf("[Redirector][TCPHandler::Handle] Unhandled setup error\n");
				closesocket(client);
			}
		}
	}

	bool StartSetupWorkers()
	{
		tcpSetupStopping = false;
		const DWORD processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
		const size_t workerCount = min(MaxTcpSetupWorkers, max(MinTcpSetupWorkers, static_cast<size_t>(processors) * 2));
		try
		{
			tcpSetupWorkers.reserve(workerCount);
			for (size_t i = 0; i < workerCount; ++i)
				tcpSetupWorkers.emplace_back(TcpSetupWorker);
		}
		catch (...)
		{
			tcpSetupStopping = true;
			tcpSetupReady.notify_all();
			for (auto& worker : tcpSetupWorkers)
				if (worker.joinable())
					worker.join();
			tcpSetupWorkers.clear();
			return false;
		}
		return true;
	}

	void StopSetupWorkers()
	{
		tcpSetupStopping = true;
		queue<SOCKET> pending;
		{
			lock_guard<mutex> lock(tcpSetupLock);
			pending.swap(tcpSetupQueue);
		}
		while (!pending.empty())
		{
			closesocket(pending.front());
			pending.pop();
		}
		tcpSetupReady.notify_all();
		for (auto& worker : tcpSetupWorkers)
			if (worker.joinable())
				worker.join();
		tcpSetupWorkers.clear();
	}

	bool StartSession(const shared_ptr<TcpSession>& session)
	{
		const SOCKET client = session->client.load();
		const SOCKET remoteSocket = session->remote->GetSocket();
		if (client == INVALID_SOCKET || remoteSocket == INVALID_SOCKET ||
			CreateIoCompletionPort(reinterpret_cast<HANDLE>(client), tcpCompletionPort, 0, 0) == NULL ||
			CreateIoCompletionPort(reinterpret_cast<HANDLE>(remoteSocket), tcpCompletionPort, 0, 0) == NULL)
			return false;

		session->toRemote.session = session.get();
		session->toRemote.source = client;
		session->toRemote.destination = remoteSocket;
		session->toClient.session = session.get();
		session->toClient.source = remoteSocket;
		session->toClient.destination = client;
		PostReceive(&session->toRemote);
		PostReceive(&session->toClient);
		return true;
	}

}

bool TCPHandler::INIT()
{
	FREE();

	const SOCKET client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (client == INVALID_SOCKET)
	{
		printf("[Redirector][TCPHandler::INIT] Create socket failed: %d\n", WSAGetLastError());
		return false;
	}

	int v6only = 0;
	if (setsockopt(client, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&v6only), sizeof(v6only)) == SOCKET_ERROR)
	{
		printf("[Redirector][TCPHandler::INIT] Set socket option failed: %d\n", WSAGetLastError());
		closesocket(client);
		return false;
	}

	SOCKADDR_IN6 addr;
	IN6ADDR_SETANY(&addr);
	if (bind(client, reinterpret_cast<PSOCKADDR>(&addr), sizeof(addr)) == SOCKET_ERROR)
	{
		printf("[Redirector][TCPHandler::INIT] Bind socket failed: %d\n", WSAGetLastError());
		closesocket(client);
		return false;
	}
	if (listen(client, 1024) == SOCKET_ERROR)
	{
		printf("[Redirector][TCPHandler::INIT] Listen socket failed: %d\n", WSAGetLastError());
		closesocket(client);
		return false;
	}

	int addrLength = sizeof(addr);
	if (getsockname(client, reinterpret_cast<PSOCKADDR>(&addr), &addrLength) == SOCKET_ERROR)
	{
		printf("[Redirector][TCPHandler::INIT] Get listen address failed: %d\n", WSAGetLastError());
		closesocket(client);
		return false;
	}
	tcpListen = addr.sin6_port;

	if (!StartIoWorkers())
	{
		printf("[Redirector][TCPHandler::INIT] Create IOCP workers failed: %d\n", GetLastError());
		closesocket(client);
		tcpListen = 0;
		return false;
	}
	if (!StartSetupWorkers())
	{
		printf("[Redirector][TCPHandler::INIT] Create setup workers failed\n");
		closesocket(client);
		tcpListen = 0;
		StopIoWorkers();
		return false;
	}

	try
	{
		lock_guard<mutex> lock(tcpLock);
		tcpSocket = client;
		tcpStopping = false;
		tcpAcceptThread = thread(TCPHandler::Accept, client);
	}
	catch (...)
	{
		tcpStopping = true;
		closesocket(client);
		tcpListen = 0;
		StopSetupWorkers();
		StopIoWorkers();
		return false;
	}
	return true;
}

void TCPHandler::FREE()
{
	SOCKET listenSocket = INVALID_SOCKET;
	thread acceptThread;
	{
		lock_guard<mutex> lock(tcpLock);
		tcpStopping = true;
		listenSocket = tcpSocket;
		tcpSocket = INVALID_SOCKET;
		tcpListen = 0;
		if (tcpAcceptThread.joinable())
			acceptThread = move(tcpAcceptThread);
		tcpContext.clear();
	}

	if (listenSocket != INVALID_SOCKET)
	{
		shutdown(listenSocket, SD_BOTH);
		closesocket(listenSocket);
	}
	if (acceptThread.joinable())
		acceptThread.join();
	StopSetupWorkers();

	vector<shared_ptr<TcpSession>> sessions;
	{
		lock_guard<mutex> lock(tcpSessionLock);
		sessions = tcpSessions;
	}
	for (const auto& session : sessions)
		session->Stop();

	{
		unique_lock<mutex> sessionLock(tcpSessionLock);
		tcpSessionsStopped.wait(sessionLock, [] { return tcpSessions.empty(); });
	}
	StopIoWorkers();
}

void TCPHandler::CreateHandler(SOCKADDR_IN6 client, SOCKADDR_IN6 remote)
{
	lock_guard<mutex> lock(tcpLock);
	const auto id = client.sin6_family == AF_INET ? reinterpret_cast<PSOCKADDR_IN>(&client)->sin_port : client.sin6_port;
	tcpContext[id] = remote;
}

void TCPHandler::DeleteHandler(SOCKADDR_IN6 client)
{
	lock_guard<mutex> lock(tcpLock);
	const auto id = client.sin6_family == AF_INET ? reinterpret_cast<PSOCKADDR_IN>(&client)->sin_port : client.sin6_port;
	tcpContext.erase(id);
}

void TCPHandler::Accept(SOCKET listenSocket)
{
	while (!tcpStopping)
	{
		const SOCKET client = accept(listenSocket, NULL, NULL);
		if (client == INVALID_SOCKET)
		{
			const int lastError = WSAGetLastError();
			if (tcpStopping || lastError == WSAEINTR)
				return;
			printf("[Redirector][TCPHandler::Accept] Accept client failed: %d\n", lastError);
			return;
		}

		int noDelay = 1;
		setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
		bool queued = false;
		{
			lock_guard<mutex> lock(tcpSetupLock);
			// SOCKS negotiation is intentionally isolated from the accept thread.
			// A bounded queue prevents a connection burst from creating one native
			// thread per flow or consuming unbounded memory.
			if (!tcpStopping && !tcpSetupStopping && tcpSetupQueue.size() < MaxPendingTcpSetups)
			{
				tcpSetupQueue.push(client);
				queued = true;
			}
		}
		if (queued)
			tcpSetupReady.notify_one();
		else
			closesocket(client);
	}
}

void TCPHandler::Handle(SOCKET client)
{
	SOCKADDR_IN6 addr;
	int addrLength = sizeof(addr);
	if (getpeername(client, reinterpret_cast<PSOCKADDR>(&addr), &addrLength) == SOCKET_ERROR)
	{
		closesocket(client);
		return;
	}
	const USHORT id = addr.sin6_family == AF_INET ? reinterpret_cast<PSOCKADDR_IN>(&addr)->sin_port : addr.sin6_port;

	SOCKADDR_IN6 target;
	{
		lock_guard<mutex> lock(tcpLock);
		auto it = tcpContext.find(id);
		if (it == tcpContext.end())
		{
			closesocket(client);
			return;
		}
		target = it->second;
	}

	auto remote = make_shared<SocksHelper::TCP>();
	if (!remote->Connect(&target))
	{
		closesocket(client);
		return;
	}

	auto session = make_shared<TcpSession>();
	session->client = client;
	session->remote = remote;
	{
		lock_guard<mutex> lock(tcpSessionLock);
		if (tcpStopping)
		{
			session->Stop();
			closesocket(client);
			return;
		}
		tcpSessions.push_back(session);
	}

	if (!StartSession(session))
		AbortSession(session);
}
