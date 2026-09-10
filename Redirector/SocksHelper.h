#pragma once
#ifndef SOCKSHELPER_H
#define SOCKSHELPER_H
#include "Based.h"

namespace SocksHelper
{
	SOCKET Connect();
	bool Handshake(SOCKET client);
	bool SplitAddr(SOCKET client, PSOCKADDR_IN6 addr);

	typedef class TCP
	{
	public:
		~TCP();

		bool Connect(PSOCKADDR_IN6 target);
		void Stop();
		SOCKET GetSocket() const;

		int Send(const char* buffer, int length);
		int Read(char* buffer, int length);

	private:
		// A TCP relay socket is assigned before either forwarding thread starts
		// and is only closed after both threads have stopped.  Atomic reads avoid
		// serialising opposite directions of every relayed packet on one mutex.
		atomic<SOCKET> tcpSocket = INVALID_SOCKET;
	} *PTCP;

	typedef class UDP
	{
	public:
		~UDP();

		bool EnsureReady();
		bool TryStartReceiver();
		void ResetReceiver();
		void Stop();

		int Send(PSOCKADDR_IN6 target, const char* buffer, int length);
		int Read(PSOCKADDR_IN6 target, char* buffer, int length, PTIMEVAL timeout);
		static int DecodePacket(PSOCKADDR_IN6 target, char* buffer, int length);
		bool AssociateReceivePort(HANDLE completionPort);
		bool BeginReceive(WSABUF* buffer, OVERLAPPED* overlapped);

	private:
		bool AssociateLocked();
		bool CreateUDPLocked();
		void Run();
		void CloseSockets();

		mutex socketLock;
		thread keepAliveThread;
		atomic_bool stopping = false;
		atomic_bool receiverStarted = false;
		SOCKET tcpSocket = INVALID_SOCKET;
		SOCKET udpSocket = INVALID_SOCKET;
		SOCKADDR_IN6 address = { 0 };
	} *PUDP;
};

#endif
