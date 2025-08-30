#include "Client.h"
#include <iostream>
#include <exception>
#include <stdexcept>
#include <WS2tcpip.h>
#include <thread>
#include "EncryptionManager.h"

Client::Client()
{
	// we connect to server that uses TCP. thats why SOCK_STREAM & IPPROTO_TCP
	_clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (_clientSocket == INVALID_SOCKET)
		throw std::runtime_error(std::string(__FUNCTION__) + " - socket");
}

Client::~Client()
{
	try
	{
		// the only use of the destructor should be for freeing 
		// resources that was allocated in the constructor
		closesocket(_clientSocket);
	}
	catch (...) {}
}


void Client::connectToServer(std::string serverIP, int port)
{
	struct sockaddr_in sa = { 0 };

	sa.sin_port = htons(port); // port that server will listen to
	sa.sin_family = AF_INET;   // must be AF_INET

	if (inet_pton(AF_INET, serverIP.c_str(), &sa.sin_addr) <= 0) {
		throw std::runtime_error("Invalid IP address format");
	}

	// the process will not continue until the server accepts the client
	int status = connect(_clientSocket, (struct sockaddr*)&sa, sizeof(sa));

	if (status == INVALID_SOCKET)
		throw std::runtime_error("Cant connect to server");

	manageConnection();
}

void Client::sendData(const std::string& data)
{
	send(_clientSocket, data.c_str(), data.size(), 0);
}

std::string Client::receiveData()
{
	char buffer[1024];
	int bytesReceived = recv(_clientSocket, buffer, sizeof(buffer), 0);
	if (bytesReceived > 0) {
		return std::string(buffer, bytesReceived);
	}
	return "";
}
std::vector<unsigned char> Client::getPartFromSocketVec(const SOCKET sc, const int bytesNum, const int flags)
{
	if (bytesNum == 0)
	{
		return {};
	}

	std::vector<unsigned char> buffer(bytesNum);
	int res = recv(sc, reinterpret_cast<char*>(buffer.data()), bytesNum, flags);

	if (res == 0)
	{
		// Client disconnected
		return {};
	}
	else if (res == INVALID_SOCKET)
	{
		std::string s = "Error while receiving from socket: " + std::to_string(sc);
		throw std::exception(s.c_str());
	}

	// Resize to actual bytes received
	buffer.resize(res);

	return buffer;
}


void Client::sendEncryptedData(const SOCKET sc, const std::vector<unsigned char>& encryptedData)
{
	int dataSize = static_cast<int>(encryptedData.size());

	if (dataSize == 0) {
		return; // nothing to send
	}

	int sent = send(sc,
		reinterpret_cast<const char*>(encryptedData.data()),
		dataSize,
		0);

	if (sent == SOCKET_ERROR || sent != dataSize) {
		throw std::runtime_error("Failed to send all encrypted data in one call");
	}
}

void Client::manageConnection()
{
	std::string publicRSAKey = "";

	publicRSAKey = receiveData();

	std::cout << "Received RSA Public Key" << std::endl;

	if (!publicRSAKey.empty())
	{
		EncryptionManager encManager(publicRSAKey);

		// Use encManager to get encrypted AES key, send it, etc.
		auto encryptedKey = encManager.getEncryptedAESKey();

		// send encryptedKey over the socket
		sendData(std::string(encryptedKey.begin(), encryptedKey.end()));

		// Get client ID
		std::cout << "Enter your client ID: ";
		std::string clientId;
		std::getline(std::cin, clientId);

		// Send encrypted client ID
		std::vector<unsigned char> clientIdVec(clientId.begin(), clientId.end());
		sendEncryptedData(_clientSocket, encManager.aesEncrypt(clientIdVec, encManager.getAESKey()));

		// Receive welcome message
		std::vector<unsigned char> decryptedAES = encManager.aesDecrypt(getPartFromSocketVec(_clientSocket, 512, 0), encManager.getAESKey());
		std::string welcomeMsg(decryptedAES.begin(), decryptedAES.end());
		std::cout << "Server says: " << welcomeMsg << std::endl;

		// Start message receiving thread
		std::thread receiveThread(&Client::receiveMessages, this, std::ref(encManager));
		receiveThread.detach();

		// Main interaction loop
		std::cout << "\nCommands:" << std::endl;
		std::cout << "- Type 'LIST' to see connected clients" << std::endl;
		std::cout << "- Type 'TARGET_ID:MESSAGE' to send message to a specific client" << std::endl;
		std::cout << "- Type 'Goodbye' to exit" << std::endl;

		while (true)
		{
			std::string userInput;
			std::cout << "\n> ";
			std::getline(std::cin, userInput);

			if (userInput.empty()) continue;

			std::vector<unsigned char> inputVec(userInput.begin(), userInput.end());
			sendEncryptedData(_clientSocket, encManager.aesEncrypt(inputVec, encManager.getAESKey()));

			if (userInput == "Goodbye")
			{
				break;
			}

			// Wait for response (except for Goodbye)
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

		std::cout << "Disconnected from server." << std::endl;
	}
}

void Client::receiveMessages(EncryptionManager& encManager)
{
	try
	{
		while (true)
		{
			std::vector<unsigned char> decryptedData = encManager.aesDecrypt(getPartFromSocketVec(_clientSocket, 512, 0), encManager.getAESKey());
			if (decryptedData.empty())
			{
				break; // Connection closed
			}

			std::string message(decryptedData.begin(), decryptedData.end());
			std::cout << "\n" << message << std::endl;
			std::cout << "> ";
			std::cout.flush();
		}
	}
	catch (const std::exception& e)
	{
		// Connection closed or error occurred
	}
}