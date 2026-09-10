#pragma once
#ifndef TCPHANDLER_H
#define TCPHANDLER_H
#include "Based.h"
#include "SocksHelper.h"

namespace TCPHandler
{
	bool INIT();
	void FREE();

	void CreateHandler(SOCKADDR_IN6 client, SOCKADDR_IN6 remote);
	void DeleteHandler(SOCKADDR_IN6 client);

	void Accept(SOCKET listenSocket);
	void Handle(SOCKET client);
}

#endif
