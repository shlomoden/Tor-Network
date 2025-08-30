#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <queue>
#include <map>
#include <iostream>
#include <string>
#include <cstring>
#include <mutex>
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <condition_variable>
#include <fstream>
#include <ctime>
#include <vector>
#include "Helper.h";
#include "EncryptionManager.h"

struct ClientInfo {
	SOCKET socket;
	std::string clientId;
	std::vector<unsigned char> aesKey;
};

class Communicator
{
public:
	Communicator(EncryptionManager& encMgr);
	~Communicator();
	void serve(int port);
private:
	void acceptClient();
	void clientHandler(SOCKET clientSocket);
	void acceptLoop();
	void broadcastMessage(const std::string& senderClientId, const std::string& message, const std::string& targetClientId);
	std::string getClientList();
	void removeClient(SOCKET clientSocket);

	SOCKET _communicatorSocket;
	static std::vector<ClientInfo> m_clients;
	static std::mutex m_clientsMutex;
	EncryptionManager& encryptionManager;
};