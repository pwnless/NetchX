#include "SocksHelper.h"

#include "Utils.h"

// MSWSock.h exposes SO_UPDATE_CONNECT_CONTEXT when the target SDK's
// _WIN32_WINNT default is at least Windows XP.  Keep the literal available
// for older project toolsets too: WSAConnectByName has required this option
// since it was introduced on Windows Vista.
#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010
#endif

extern wstring tgtHost;
extern wstring tgtPort;
extern string tgtUsername;
extern string tgtPassword;

namespace
{
	bool SendAll(SOCKET socket, const char* buffer, int length)
	{
		for (int sent = 0; sent < length;)
		{
			const int result = send(socket, buffer + sent, length - sent, 0);
			if (result == SOCKET_ERROR || result == 0)
				return false;

			sent += result;
		}

		return true;
	}

	bool ReceiveExact(SOCKET socket, char* buffer, int length)
	{
		for (int received = 0; received < length;)
		{
			const int result = recv(socket, buffer + received, length - received, 0);
			if (result == SOCKET_ERROR || result == 0)
				return false;

			received += result;
		}

		return true;
	}
}

SOCKET SocksHelper::Connect()
{
	auto client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (client == INVALID_SOCKET)
	{
		printf("[Redirector][SocksHelper::Connect] Create socket failed: %d\n", WSAGetLastError());
		return INVALID_SOCKET;
	}

	{
		int v6only = 0;
		if (setsockopt(client, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only)) == SOCKET_ERROR)
		{
			printf("[Redirector][SocksHelper::Connect] Set socket option failed: %d\n", WSAGetLastError());

			closesocket(client);
			return INVALID_SOCKET;
		}
	}

	// A proxy commonly relays request/response protocols with short writes.
	// Avoid adding Nagle delay at its SOCKS-facing hop; bulk transfers still
	// use the normal TCP congestion control and coalescing in the kernel.
	int noDelay = 1;
	setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));

	timeval timeout{};
	timeout.tv_sec = 4;

	if (!WSAConnectByNameW(client, (LPWSTR)tgtHost.c_str(), (LPWSTR)tgtPort.c_str(), NULL, NULL, NULL, NULL, &timeout, NULL))
	{
		printf("[Redirector][SocksHelper::Connect] Connect to remote server failed: %d\n", WSAGetLastError());

		closesocket(client);
		return INVALID_SOCKET;
	}

	// WSAConnectByName does not update the socket's connect context itself.
	// Without this call getpeername/shutdown can report WSAENOTCONN even after
	// the SOCKS handshake has exchanged data, which prevents propagating TCP
	// half-closes to the proxy.
	if (setsockopt(client, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR)
	{
		printf("[Redirector][SocksHelper::Connect] Update connect context failed: %d\n", WSAGetLastError());
		closesocket(client);
		return INVALID_SOCKET;
	}
	{
		DWORD returned = 0;

		tcp_keepalive data = { 1, 120000, 10000 };
		WSAIoctl(client, SIO_KEEPALIVE_VALS, &data, sizeof(data), NULL, 0, &returned, NULL, NULL);
	}

	DWORD ioTimeout = 5000;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ioTimeout, sizeof(ioTimeout));
	setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ioTimeout, sizeof(ioTimeout));

	return client;
}

bool SocksHelper::Handshake(SOCKET client)
{
	// RFC 1929 encodes both fields in one octet.  Truncating with '& 0xff'
	// changes credentials (256 becomes zero) and can silently authenticate the
	// wrong identity, so reject values the protocol cannot represent.
	if (tgtUsername.size() > 255 || tgtPassword.size() > 255)
	{
		puts("[Redirector][SocksHelper::Handshake] Username or password exceeds 255 bytes");
		return false;
	}

	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	/* Client Hello */
	buffer[0] = 0x05;
	buffer[1] = 0x02;
	buffer[2] = 0x00;
	buffer[3] = 0x02;
	if (!SendAll(client, buffer, 4))
	{
		printf("[Redirector][SocksHelper::Handshake] Send client hello failed: %d\n", WSAGetLastError());
		return false;
	}

	/* Server Choice */
	if (!ReceiveExact(client, buffer, 2))
	{
		printf("[Redirector][SocksHelper::Handshake] Receive server choice failed: %d\n", WSAGetLastError());
		return false;
	}

	if (buffer[0] != 0x05)
		return false;

	/* Authentication */
	if (buffer[1] == 0x02)
	{
		memset(buffer, 0, sizeof(buffer));
		buffer[0] = 0x01;

		BYTE ulength = static_cast<BYTE>(tgtUsername.length());
		BYTE plength = static_cast<BYTE>(tgtPassword.length());

		/* Username */
		buffer[1] = 0x00;
		if (ulength != 0)
		{
			buffer[1] = ulength;
			memcpy(buffer + 1 + 1, tgtUsername.c_str(), ulength);
		}

		/* Password */
		buffer[1 + 1 + ulength] = 0x00;
		if (plength != 0)
		{
			buffer[1 + 1 + ulength] = plength;
			memcpy(buffer + 1 + 1 + ulength + 1, tgtPassword.c_str(), plength);
		}

		auto length = 1 + 1 + ulength + 1 + plength;
		if (!SendAll(client, buffer, length))
		{
			printf("[Redirector][SocksHelper::Handshake] Send authentication request failed: %d\n", WSAGetLastError());
			return false;
		}

		/* Server Response */
		if (!ReceiveExact(client, buffer, 2))
		{
			printf("[Redirector][SocksHelper::Handshake] Receive server response failed: %d\n", WSAGetLastError());
			return false;
		}

		if (buffer[1] != 0x00)
		{
			puts("[Redirector][SocksHelper::Handshake] Authentication failed");
			return false;
		}
	}
	else if (buffer[1] != 0x00)
	{
		return false;
	}

	return true;
}

bool SocksHelper::SplitAddr(SOCKET client, PSOCKADDR_IN6 addr)
{
	char addrType;
	if (!ReceiveExact(client, (char*)&addrType, 1))
	{
		printf("[Redirector][SocksHelper::SplitAddr] Read address type failed: %d\n", WSAGetLastError());
		return false;
	}

	if (addrType == 0x01)
	{
		auto ipv4 = (PSOCKADDR_IN)addr;
		ipv4->sin_family = AF_INET;

		if (!ReceiveExact(client, (char*)&ipv4->sin_addr, 4))
		{
			printf("[Redirector][SocksHelper::SplitAddr] Read IPv4 address failed: %d\n", WSAGetLastError());
			return false;
		}

		if (!ReceiveExact(client, (char*)&ipv4->sin_port, 2))
		{
			printf("[Redirector][SocksHelper::SplitAddr] Read IPv4 port failed: %d\n", WSAGetLastError());
			return false;
		}
	}
	else if (addrType == 0x04)
	{
		addr->sin6_family = AF_INET6;

		if (!ReceiveExact(client, (char*)&addr->sin6_addr, 16))
		{
			printf("[Redirector][SocksHelper::SplitAddr] Read IPv6 address failed: %d\n", WSAGetLastError());
			return false;
		}

		if (!ReceiveExact(client, (char*)&addr->sin6_port, 2))
		{
			printf("[Redirector][SocksHelper::SplitAddr] Read IPv6 port failed: %d\n", WSAGetLastError());
			return false;
		}
	}
	else
	{
		printf("[Redirector][SocksHelper::SplitAddr] Unsupported address family: %d\n", addrType);
		return false;
	}

	return true;
}

SocksHelper::TCP::~TCP()
{
	Stop();

	const SOCKET socket = tcpSocket.exchange(INVALID_SOCKET);
	if (socket != INVALID_SOCKET)
		closesocket(socket);
}

void SocksHelper::TCP::Stop()
{
	const SOCKET socket = tcpSocket.load();
	if (socket != INVALID_SOCKET)
		shutdown(socket, SD_BOTH);
}

SOCKET SocksHelper::TCP::GetSocket() const
{
	return tcpSocket.load();
}
bool SocksHelper::TCP::Connect(PSOCKADDR_IN6 target)
{
	const SOCKET socket = SocksHelper::Connect();
	if (socket == INVALID_SOCKET)
		return false;
	tcpSocket = socket;

	if (!SocksHelper::Handshake(socket))
		return false;

	/* Connect Request */
	if (target->sin6_family == AF_INET)
	{
		char buffer[10]{};
		buffer[0] = 0x05;
		buffer[1] = 0x01;
		buffer[2] = 0x00;
		buffer[3] = 0x01;

		auto addr = (PSOCKADDR_IN)target;
		memcpy(buffer + 4, &addr->sin_addr, 4);
		memcpy(buffer + 8, &addr->sin_port, 2);

		if (!SendAll(socket, buffer, 10))
		{
			printf("[Redirector][SocksHelper::TCP::Connect] Send connect request failed: %d\n", WSAGetLastError());
			return false;
		}
	}
	else
	{
		char buffer[22]{};
		buffer[0] = 0x05;
		buffer[1] = 0x01;
		buffer[2] = 0x00;
		buffer[3] = 0x04;

		auto addr = target;
		memcpy(buffer + 4, &addr->sin6_addr, 16);
		memcpy(buffer + 20, &addr->sin6_port, 2);

		if (!SendAll(socket, buffer, sizeof(buffer)))
		{
			printf("[Redirector][SocksHelper::TCP::Connect] Send connect request failed: %d\n", WSAGetLastError());
			return false;
		}
	}

	/* Server Response */
	char buffer[3];
	if (!ReceiveExact(socket, buffer, 3))
	{
		printf("[Redirector][SocksHelper::TCP::Connect] Receive server response failed: %d\n", WSAGetLastError());
		return false;
	}

	if (buffer[0] != 0x05 || buffer[1] != 0x00 || buffer[2] != 0x00)
		return false;
	SOCKADDR_IN6 addr;
	return SocksHelper::SplitAddr(socket, &addr);
}
int SocksHelper::TCP::Send(const char* buffer, int length)
{
	if (length < 0)
		return SOCKET_ERROR;

	const SOCKET socket = tcpSocket.load();
	if (socket != INVALID_SOCKET && SendAll(socket, buffer, length))
		return length;

	return SOCKET_ERROR;
}
int SocksHelper::TCP::Read(char* buffer, int length)
{
	if (length < 0)
		return SOCKET_ERROR;

	const SOCKET socket = tcpSocket.load();
	if (socket != INVALID_SOCKET)
		return recv(socket, buffer, length, 0);

	return SOCKET_ERROR;
}

SocksHelper::UDP::~UDP()
{
	Stop();
	CloseSockets();
}

void SocksHelper::UDP::CloseSockets()
{
	lock_guard<mutex> lock(socketLock);
	if (tcpSocket != INVALID_SOCKET)
	{
		closesocket(tcpSocket);
		tcpSocket = INVALID_SOCKET;
	}
	if (udpSocket != INVALID_SOCKET)
	{
		closesocket(udpSocket);
		udpSocket = INVALID_SOCKET;
	}
}

void SocksHelper::UDP::Stop()
{
	stopping = true;
	SOCKET tcp = INVALID_SOCKET;
	SOCKET udp = INVALID_SOCKET;
	{
		lock_guard<mutex> lock(socketLock);
		tcp = tcpSocket;
		udp = udpSocket;
		tcpSocket = INVALID_SOCKET;
		udpSocket = INVALID_SOCKET;
	}

	if (tcp != INVALID_SOCKET)
	{
		shutdown(tcp, SD_BOTH);
		closesocket(tcp);
	}
	if (udp != INVALID_SOCKET)
	{
		// Complete any IOCP WSARecv before releasing the socket.  This lets the
		// shared receive workers drain their operation objects deterministically.
		CancelIoEx((HANDLE)udp, NULL);
		shutdown(udp, SD_BOTH);
		// shutdown() does not reliably interrupt a pending UDP receive() on
		// Windows.  Closing the handle guarantees cancellation is delivered.
		closesocket(udp);
	}

	if (keepAliveThread.joinable())
	{
		if (keepAliveThread.get_id() == this_thread::get_id())
			keepAliveThread.detach();
		else
			keepAliveThread.join();
	}
}

bool SocksHelper::UDP::AssociateLocked()
{
	tcpSocket = SocksHelper::Connect();
	if (tcpSocket == INVALID_SOCKET)
		return false;

	if (!SocksHelper::Handshake(tcpSocket))
		return false;

	char buffer[10]{};
	buffer[0] = 0x05;
	buffer[1] = 0x03;
	buffer[3] = 0x01;

	if (!SendAll(tcpSocket, buffer, 10))
	{
		printf("[Redirector][SocksHelper::UDP::Associate] Send udp associate request failed: %d\n", WSAGetLastError());
		return false;
	}

	if (!ReceiveExact(tcpSocket, buffer, 3))
	{
		printf("[Redirector][SocksHelper::UDP::Associate] Receive udp associate response failed: %d\n", WSAGetLastError());
		return false;
	}

	if (buffer[0] != 0x05 || buffer[1] != 0x00 || buffer[2] != 0x00)
	{
		printf("[Redirector][SocksHelper::UDP::Associate] UDP associate failed: %d\n", buffer[1]);
		return false;
	}

	return SocksHelper::SplitAddr(tcpSocket, &address);
}

bool SocksHelper::UDP::CreateUDPLocked()
{
	if (address.sin6_family == AF_INET)
	{
		udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (udpSocket == INVALID_SOCKET)
		{
			printf("[Redirector][SocksHelper::UDP::CreateUDP] Create IPv4 socket failed: %d\n", WSAGetLastError());
			return false;
		}

		SOCKADDR_IN bindaddr;
		memset(&bindaddr, 0, sizeof(SOCKADDR_IN));
		bindaddr.sin_family = AF_INET;

		if (bind(udpSocket, (PSOCKADDR)&bindaddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
		{
			printf("[Redirector][SocksHelper::UDP::CreateUDP] Listen IPv4 socket failed: %d\n", WSAGetLastError());
			return false;
		}
	}
	else
	{
		udpSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (udpSocket == INVALID_SOCKET)
		{
			printf("[Redirector][SocksHelper::UDP::CreateUDP] Create IPv6 socket failed: %d\n", WSAGetLastError());
			return false;
		}

		SOCKADDR_IN6 bindaddr;
		memset(&bindaddr, 0, sizeof(SOCKADDR_IN6));
		bindaddr.sin6_family = AF_INET6;

		if (bind(udpSocket, (PSOCKADDR)&bindaddr, sizeof(SOCKADDR_IN6)) == SOCKET_ERROR)
		{
			printf("[Redirector][SocksHelper::UDP::CreateUDP] Listen IPv6 socket failed: %d\n", WSAGetLastError());
			return false;
		}
	}

	if (connect(udpSocket, (PSOCKADDR)&address, address.sin6_family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6)) == SOCKET_ERROR)
	{
		printf("[Redirector][SocksHelper::UDP::CreateUDP] Connect relay socket failed: %d\n", WSAGetLastError());
		closesocket(udpSocket);
		udpSocket = INVALID_SOCKET;
		return false;
	}

	keepAliveThread = thread(&SocksHelper::UDP::Run, this);
	return true;
}

bool SocksHelper::UDP::EnsureReady()
{
	lock_guard<mutex> lock(socketLock);
	if (stopping)
		return false;

	if (tcpSocket == INVALID_SOCKET && !AssociateLocked())
	{
		if (tcpSocket != INVALID_SOCKET)
		{
			closesocket(tcpSocket);
			tcpSocket = INVALID_SOCKET;
		}
		return false;
	}

	if (udpSocket == INVALID_SOCKET && !CreateUDPLocked())
	{
		if (udpSocket != INVALID_SOCKET)
		{
			closesocket(udpSocket);
			udpSocket = INVALID_SOCKET;
		}
		return false;
	}

	return true;
}

bool SocksHelper::UDP::TryStartReceiver()
{
	bool expected = false;
	return !stopping && receiverStarted.compare_exchange_strong(expected, true);
}

void SocksHelper::UDP::ResetReceiver()
{
	receiverStarted = false;
}

void SocksHelper::UDP::Run()
{
	SOCKET socket;
	{
		lock_guard<mutex> lock(socketLock);
		socket = tcpSocket;
	}

	char buffer[1];
	while (!stopping && socket != INVALID_SOCKET)
	{
		if (!ReceiveExact(socket, buffer, sizeof(buffer)) || !SendAll(socket, buffer, sizeof(buffer)))
			break;
	}

	stopping = true;
	SOCKET udp;
	{
		lock_guard<mutex> lock(socketLock);
		udp = udpSocket;
	}
	if (udp != INVALID_SOCKET)
		shutdown(udp, SD_BOTH);
}
int SocksHelper::UDP::Send(PSOCKADDR_IN6 target, const char* buffer, int length)
{
	if (length < 0 || stopping)
		return SOCKET_ERROR;

	if (target->sin6_family != AF_INET && target->sin6_family != AF_INET6)
		return SOCKET_ERROR;

	SOCKET socket;
	{
		lock_guard<mutex> lock(socketLock);
		socket = udpSocket;
	}
	if (socket == INVALID_SOCKET)
		return SOCKET_ERROR;

	const auto headerLength = 3 + 1 + (target->sin6_family == AF_INET ? 4 : 16) + 2;
	thread_local vector<char> data;
	data.resize(headerLength + static_cast<size_t>(length));
	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = (target->sin6_family == AF_INET) ? 0x01 : 0x04;

	if (target->sin6_family == AF_INET)
	{
		auto ipv4 = (PSOCKADDR_IN)target;

		memcpy(data.data() + 4, &ipv4->sin_addr, 4);
		memcpy(data.data() + 8, &ipv4->sin_port, 2);
	}
	else
	{
		memcpy(data.data() + 4, &target->sin6_addr, 16);
		memcpy(data.data() + 20, &target->sin6_port, 2);
	}

	memcpy(data.data() + headerLength, buffer, length);
	auto dataLength = headerLength + length;

	if (send(socket, data.data(), dataLength, 0) != dataLength)
	{
		printf("[Redirector][SocksHelper::UDP::Send] Send packet failed: %d\n", WSAGetLastError());
		return SOCKET_ERROR;
	}

	return length;
}

int SocksHelper::UDP::Read(PSOCKADDR_IN6 target, char* buffer, int length, PTIMEVAL timeout)
{
	if (length <= 0 || stopping)
		return SOCKET_ERROR;

	SOCKET socket;
	{
		lock_guard<mutex> lock(socketLock);
		socket = udpSocket;
	}
	if (socket == INVALID_SOCKET)
		return SOCKET_ERROR;

	if (timeout != NULL)
	{
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(socket, &fds);

		int size = select(NULL, &fds, NULL, NULL, timeout);
		if (size == 0 || size == SOCKET_ERROR)
			return size;
	}

	int size = recv(socket, buffer, length, 0);
	return DecodePacket(target, buffer, size);
}

int SocksHelper::UDP::DecodePacket(PSOCKADDR_IN6 target, char* buffer, int size)
{
	if (size == 0 || size == SOCKET_ERROR)
		return size;
	if (size < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0)
		return SOCKET_ERROR;

	SOCKADDR_IN6 addr{};
	if (buffer[3] == 0x01)
	{
		if (size < 10)
			return SOCKET_ERROR;

		auto ipv4 = (PSOCKADDR_IN)&addr;
		ipv4->sin_family = AF_INET;

		memcpy(&ipv4->sin_addr, buffer + 4, 4);
		memcpy(&ipv4->sin_port, buffer + 8, 2);

		memmove(buffer, buffer + 10, static_cast<size_t>(size - 10));
	}
	else if (buffer[3] == 0x04)
	{
		if (size < 22)
			return SOCKET_ERROR;

		addr.sin6_family = AF_INET6;

		memcpy(&addr.sin6_addr, buffer + 4, 16);
		memcpy(&addr.sin6_port, buffer + 20, 2);

		memmove(buffer, buffer + 22, static_cast<size_t>(size - 22));
	}
	else
	{
		return SOCKET_ERROR;
	}

	if (target != NULL)
		memcpy(target, &addr, sizeof(SOCKADDR_IN6));

	return size - (addr.sin6_family == AF_INET ? 10 : 22);
}

bool SocksHelper::UDP::AssociateReceivePort(HANDLE completionPort)
{
	if (completionPort == NULL)
		return false;

	lock_guard<mutex> lock(socketLock);
	if (stopping || udpSocket == INVALID_SOCKET)
		return false;

	return CreateIoCompletionPort((HANDLE)udpSocket, completionPort, 0, 0) == completionPort;
}

bool SocksHelper::UDP::BeginReceive(WSABUF* buffer, OVERLAPPED* overlapped)
{
	if (buffer == NULL || overlapped == NULL)
		return false;

	lock_guard<mutex> lock(socketLock);
	if (stopping || udpSocket == INVALID_SOCKET)
		return false;

	DWORD flags = 0;
	const int result = WSARecv(udpSocket, buffer, 1, NULL, &flags, overlapped, NULL);
	return result == 0 || WSAGetLastError() == WSA_IO_PENDING;
}
