#pragma once

#include <WinSock2.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

class EncryptionManager;

class Client
{
public:
    Client();
    ~Client();
    void connectToServer(std::string serverIP, int port);
    void sendData(const std::string& data);
    std::string receiveData();

    std::vector<unsigned char> getPartFromSocketVec(const SOCKET sc, const int bytesNum, const int flags);
    void sendEncryptedData(const SOCKET sc, const std::vector<unsigned char>& encryptedData);

    void manageConnection();
    void receiveMessages(EncryptionManager& encManager);

private:
    SOCKET _clientSocket;
};