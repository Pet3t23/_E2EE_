#include "NetworkHelper.h"

/**
 * @brief Constructor. Inicializa Winsock y establece valores por defecto.
 *
 * Si la inicializaci�n de Winsock falla, se muestra un mensaje de error y
 * la bandera m_initialized queda en false.
 */
NetworkHelper::NetworkHelper()
    : m_serverSocket(INVALID_SOCKET), m_initialized(false) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
    }
    else {
        m_initialized = true;
    }
}

/**
 * @brief Destructor. Cierra el socket y limpia Winsock si fue inicializado.
 */
NetworkHelper::~NetworkHelper() {
    if (m_serverSocket != INVALID_SOCKET) {
        closesocket(m_serverSocket);
    }
    if (m_initialized) {
        WSACleanup();
    }
}

/**
 * @brief Inicia un servidor TCP en el puerto especificado y lo deja en escucha.
 * @param port Puerto TCP.
 * @return true si el servidor inici� correctamente, false en caso de error.
 */
bool NetworkHelper::StartServer(int port) {
    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_serverSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        return false;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Error binding socket: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Error listening on socket: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    std::cout << "Server started on port " << port << std::endl;
    return true;
}

/**
 * @brief Acepta la conexi�n de un cliente entrante.
 * @return SOCKET del cliente o INVALID_SOCKET si falla.
 */
SOCKET NetworkHelper::AcceptClient() {
    SOCKET clientSocket = accept(m_serverSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Error accepting client: " << WSAGetLastError() << std::endl;
        return INVALID_SOCKET;
    }
    std::cout << "Client connected." << std::endl;
    return clientSocket;
}

/**
 * @brief Conecta a un servidor remoto.
 * @param ip Direcci�n IP del servidor.
 * @param port Puerto del servidor.
 * @return true si la conexi�n fue exitosa, false en caso contrario.
 */
bool NetworkHelper::ConnectToServer(const std::string& ip, int port) {
    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_serverSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        return false;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddress.sin_addr);

    if (connect(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }
    std::cout << "Connected to server at " << ip << ":" << port << std::endl;
    return true;
}

/**
 * @brief Env�a una cadena de texto por el socket.
 */
bool NetworkHelper::SendData(SOCKET socket, const std::string& data) {
    return send(socket, data.c_str(), static_cast<int>(data.size()), 0) != SOCKET_ERROR;
}

/**
 * @brief Env�a datos binarios por el socket.
 */
bool NetworkHelper::SendData(SOCKET socket, const std::vector<unsigned char>& data) {
    return SendAll(socket, data.data(), static_cast<int>(data.size()));
}

/**
 * @brief Recibe una cadena de texto desde el socket.
 * @return Cadena recibida.
 */
std::string NetworkHelper::ReceiveData(SOCKET socket) {
    char buffer[4096] = {};
    int len = recv(socket, buffer, sizeof(buffer), 0);
    return std::string(buffer, len);
}

/**
 * @brief Recibe datos binarios de tama�o fijo desde el socket.
 * @param size Cantidad de bytes a recibir.
 * @return Vector de bytes recibidos o vac�o si hay error.
 */
std::vector<unsigned char> NetworkHelper::ReceiveDataBinary(SOCKET socket, int size) {
    std::vector<unsigned char> buf(size);
    if (!ReceiveExact(socket, buf.data(), size)) return {};
    return buf;
}

/**
 * @brief Cierra un socket dado.
 */
void NetworkHelper::close(SOCKET socket) {
    closesocket(socket);
}

/**
 * @brief Env�a todos los datos indicados hasta completar el tama�o.
 */
bool NetworkHelper::SendAll(SOCKET s, const unsigned char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)data + sent, len - sent, 0);
        if (n == SOCKET_ERROR) return false;
        sent += n;
    }
    return true;
}

/**
 * @brief Recibe exactamente la cantidad de bytes especificada.
 */
bool NetworkHelper::ReceiveExact(SOCKET s, unsigned char* out, int len) {
    int recvd = 0;
    while (recvd < len) {
        int n = recv(s, (char*)out + recvd, len - recvd, 0);
        if (n <= 0) return false;
        recvd += n;
    }
    return true;
}
