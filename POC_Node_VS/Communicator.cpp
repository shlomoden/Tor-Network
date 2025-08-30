#include "Communicator.h"

std::mutex userSocketMtx;
std::mutex msgMtx;
std::condition_variable cv;
bool ready = false;

std::string msgGlb = "";

std::vector<ClientInfo> Communicator::m_clients;
std::mutex Communicator::m_clientsMutex;

Communicator::Communicator(EncryptionManager& encMgr) : encryptionManager(encMgr)
{
	// this communicator use TCP. that why SOCK_STREAM & IPPROTO_TCP
	// if the communicator use UDP we will use: SOCK_DGRAM & IPPROTO_UDP
	_communicatorSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (_communicatorSocket == INVALID_SOCKET)
		throw std::exception(__FUNCTION__ " - socket");
}

Communicator::~Communicator()
{
	try
	{
		// the only use of the destructor should be for freeing 
		// resources that was allocated in the constructor
		closesocket(_communicatorSocket);
	}
	catch (...) {}
}

void Communicator::serve(int port)
{
	struct sockaddr_in sa = { 0 };

	sa.sin_port = htons(port); // port that communicator will listen for
	sa.sin_family = AF_INET;   // must be AF_INET
	sa.sin_addr.s_addr = INADDR_ANY;    // when there are few ip's for the machine. We will use always "INADDR_ANY"

	// Connects between the socket and the configuration (port and etc..)
	if (bind(_communicatorSocket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - bind");

	// Start listening for incoming requests of clients
	if (listen(_communicatorSocket, SOMAXCONN) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - listen");
	std::cout << "Listening on port " << port << std::endl;

	std::thread acceptorThread(&Communicator::acceptLoop, this);
	acceptorThread.join();
}

void Communicator::acceptClient()
{
	// this accepts the client and create a specific socket from communicator to this client
	// the process will not continue until a client connects to the communicator
	SOCKET client_socket = accept(_communicatorSocket, NULL, NULL);
	if (client_socket == INVALID_SOCKET)
		throw std::exception(__FUNCTION__);

	std::cout << "Client accepted. communicator and client can speak" << std::endl;

	std::thread gotClient(&Communicator::clientHandler, this, client_socket);
	gotClient.detach();
}

void Communicator::clientHandler(SOCKET clientSocket)
{
	try
	{
		// ONLY FOR POC -> SO THAT THE CLIENT KNOWS THE PUBLIC KEY
		std::string encRSAPubkey = encryptionManager.getPublicKeyAsString();
		encryptionManager.printPublicKey();
		std::string sendMsg(encRSAPubkey.begin(), encRSAPubkey.end());
		Helper::sendData(clientSocket, sendMsg);

		std::vector<unsigned char> encryptedAESKey = Helper::getPartFromSocketVec(clientSocket, 512, 0);
		std::vector<unsigned char> aesKey = encryptionManager.rsaDecrypt(encryptedAESKey);

		// Get client ID
		std::vector<unsigned char> encryptedClientId = Helper::getPartFromSocketVec(clientSocket, 512, 0);
		std::vector<unsigned char> decryptedClientId = encryptionManager.aesDecrypt(encryptedClientId, aesKey);
		std::string clientId(reinterpret_cast<const char*>(decryptedClientId.data()), decryptedClientId.size());

		// Add client to list
		{
			std::lock_guard<std::mutex> lock(m_clientsMutex);
			ClientInfo client;
			client.socket = clientSocket;
			client.clientId = clientId;
			client.aesKey = aesKey;
			m_clients.push_back(client);
		}

		std::cout << "Client '" << clientId << "' connected" << std::endl;

		// Send confirmation
		std::string result = "Welcome " + clientId;
		std::vector<unsigned char> plaintextVec(result.begin(), result.end());
		std::vector<unsigned char> encryptedMsg = encryptionManager.aesEncrypt(plaintextVec, aesKey);
		Helper::sendEncryptedData(clientSocket, encryptedMsg);

		while (true)
		{
			std::vector<unsigned char> decryptedAES = encryptionManager.aesDecrypt(Helper::getPartFromSocketVec(clientSocket, 512, 0), aesKey);

			std::string plaintext(reinterpret_cast<const char*>(decryptedAES.data()), decryptedAES.size());

			if (plaintext == "Goodbye")
			{
				std::cout << "\nClient '" << clientId << "' is leaving" << std::endl;
				break;
			}
			else if (plaintext == "LIST")
			{
				// Send client list
				std::string clientList = getClientList();
				std::vector<unsigned char> listVec(clientList.begin(), clientList.end());
				std::vector<unsigned char> encryptedList = encryptionManager.aesEncrypt(listVec, aesKey);
				Helper::sendEncryptedData(clientSocket, encryptedList);
			}
			else
			{
				// Parse message format: "TARGET_CLIENT_ID:MESSAGE"
				size_t colonPos = plaintext.find(':');
				if (colonPos != std::string::npos)
				{
					std::string targetClientId = plaintext.substr(0, colonPos);
					std::string message = plaintext.substr(colonPos + 1);

					std::cout << "\nMessage from '" << clientId << "' to '" << targetClientId << "': " << message << std::endl;

					// Send message to target client
					broadcastMessage(clientId, message, targetClientId);

					// Send confirmation
					std::string result = "Message sent to " + targetClientId;
					std::vector<unsigned char> plaintextVec(result.begin(), result.end());
					std::vector<unsigned char> encryptedMsg = encryptionManager.aesEncrypt(plaintextVec, aesKey);
					Helper::sendEncryptedData(clientSocket, encryptedMsg);
				}
				else
				{
					// Invalid message format
					std::string result = "Invalid format. Use: TARGET_ID:MESSAGE";
					std::vector<unsigned char> plaintextVec(result.begin(), result.end());
					std::vector<unsigned char> encryptedMsg = encryptionManager.aesEncrypt(plaintextVec, aesKey);
					Helper::sendEncryptedData(clientSocket, encryptedMsg);
				}
			}
		}

		removeClient(clientSocket);
		std::cout << "Closed socket, Goodbye" << std::endl;
		closesocket(clientSocket);
	}
	catch (const std::exception& e)
	{
		removeClient(clientSocket);
		closesocket(clientSocket);
	}
}

void Communicator::broadcastMessage(const std::string& senderClientId, const std::string& message, const std::string& targetClientId)
{
	std::lock_guard<std::mutex> lock(m_clientsMutex);

	for (const auto& client : m_clients)
	{
		if (client.clientId == targetClientId)
		{
			try
			{
				std::string fullMessage = "From " + senderClientId + ": " + message;
				std::vector<unsigned char> plaintextVec(fullMessage.begin(), fullMessage.end());
				std::vector<unsigned char> encryptedMsg = encryptionManager.aesEncrypt(plaintextVec, client.aesKey);
				Helper::sendEncryptedData(client.socket, encryptedMsg);
			}
			catch (const std::exception& e)
			{
				std::cout << "Failed to send message to client '" << targetClientId << "'" << std::endl;
			}
			break;
		}
	}
}

std::string Communicator::getClientList()
{
	std::lock_guard<std::mutex> lock(m_clientsMutex);

	if (m_clients.empty())
	{
		return "No other clients connected";
	}

	std::string clientList = "Connected clients: ";
	for (size_t i = 0; i < m_clients.size(); ++i)
	{
		clientList += m_clients[i].clientId;
		if (i < m_clients.size() - 1)
		{
			clientList += ", ";
		}
	}

	return clientList;
}

void Communicator::removeClient(SOCKET clientSocket)
{
	std::lock_guard<std::mutex> lock(m_clientsMutex);

	m_clients.erase(
		std::remove_if(m_clients.begin(), m_clients.end(),
			[clientSocket](const ClientInfo& client) {
				return client.socket == clientSocket;
			}),
		m_clients.end()
	);
}

void Communicator::acceptLoop()
{
	while (true)
	{
		// the main thread is only accepting clients 
		// and add then to the list of handlers
		std::cout << "Waiting for client connection request" << std::endl;
		acceptClient();
	}
}