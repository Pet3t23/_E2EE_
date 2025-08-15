#include "Server.h"

/**
 * @brief Constructor que inicializa el puerto y genera las claves RSA.
 * @param port Puerto en el que el servidor escuchará conexiones.
 */
Server::Server(int port) : m_port(port), m_clientSock(-1) {
    // Generar claves RSA al construir
    m_crypto.GenerateRSAKeys();
}

/**
 * @brief Destructor. Cierra la conexión con el cliente si sigue activa.
 */
Server::~Server() {
    if (m_clientSock != -1) {
        m_net.close(m_clientSock);
    }
}

/**
 * @brief Inicia el servidor en el puerto especificado.
 * @return true si se inició correctamente, false en caso contrario.
 */
bool Server::Start() {
    std::cout << "[Server] Iniciando servidor en el puerto " << m_port << "...\n";
    return m_net.StartServer(m_port);
}

/**
 * @brief Espera la conexión de un cliente e intercambia claves para comunicación segura.
 *
 * - Acepta la conexión de un cliente.
 * - Envía la clave pública del servidor.
 * - Recibe la clave pública del cliente.
 * - Recibe la clave AES cifrada y la descifra.
 */
void Server::WaitForClient() {
    std::cout << "[Server] Esperando conexión de un cliente...\n";

    m_clientSock = m_net.AcceptClient();
    if (m_clientSock == INVALID_SOCKET) {
        std::cerr << "[Server] No se pudo aceptar cliente.\n";
        return;
    }
    std::cout << "[Server] Cliente conectado.\n";

    // 1. Enviar clave pública del servidor
    std::string serverPubKey = m_crypto.GetPublicKeyString();
    m_net.SendData(m_clientSock, serverPubKey);

    // 2. Recibir clave pública del cliente
    std::string clientPubKey = m_net.ReceiveData(m_clientSock);
    m_crypto.LoadPeerPublicKey(clientPubKey);

    // 3. Recibir clave AES cifrada
    std::vector<unsigned char> encryptedAESKey = m_net.ReceiveDataBinary(m_clientSock, 256);
    m_crypto.DecryptAESKey(encryptedAESKey);

    std::cout << "[Server] Clave AES intercambiada exitosamente.\n";
}

/**
 * @brief Recibe un único mensaje cifrado del cliente, lo descifra y lo muestra.
 */
void Server::ReceiveEncryptedMessage() {
    // 1. Recibir IV
    std::vector<unsigned char> iv = m_net.ReceiveDataBinary(m_clientSock, 16);

    // 2. Recibir mensaje cifrado
    std::vector<unsigned char> encryptedMsg = m_net.ReceiveDataBinary(m_clientSock, 128);

    // 3. Descifrar mensaje
    std::string msg = m_crypto.AESDecrypt(encryptedMsg, iv);

    // 4. Mostrar mensaje
    std::cout << "[Server] Mensaje recibido: " << msg << "\n";
}

/**
 * @brief Bucle de recepción continua de mensajes cifrados desde el cliente.
 */
void Server::StartReceiveLoop() {
    while (true) {
        // 1) IV (16 bytes)
        auto iv = m_net.ReceiveDataBinary(m_clientSock, 16);
        if (iv.empty()) {
            std::cout << "\n[Server] Conexión cerrada por el cliente.\n";
            break;
        }

        // 2) Tamaño del mensaje (4 bytes)
        auto len4 = m_net.ReceiveDataBinary(m_clientSock, 4);
        if (len4.size() != 4) {
            std::cout << "[Server] Error al recibir tamaño.\n";
            break;
        }
        uint32_t nlen = 0;
        std::memcpy(&nlen, len4.data(), 4);
        uint32_t clen = ntohl(nlen);

        // 3) Ciphertext
        auto cipher = m_net.ReceiveDataBinary(m_clientSock, static_cast<int>(clen));
        if (cipher.empty()) {
            std::cout << "[Server] Error al recibir datos.\n";
            break;
        }

        // 4) Descifrar y mostrar
        std::string plain = m_crypto.AESDecrypt(cipher, iv);
        std::cout << "\n[Cliente]: " << plain << "\nServidor: ";
        std::cout.flush();
    }
}

/**
 * @brief Bucle para enviar mensajes cifrados al cliente.
 */
void Server::SendEncryptedMessageLoop() {
    std::string msg;
    while (true) {
        std::cout << "Servidor: ";
        std::getline(std::cin, msg);
        if (msg == "/exit") break;

        std::vector<unsigned char> iv;
        auto cipher = m_crypto.AESEncrypt(msg, iv);

        // 1) IV
        m_net.SendData(m_clientSock, iv);

        // 2) Tamaño (4 bytes, network order)
        uint32_t clen = static_cast<uint32_t>(cipher.size());
        uint32_t nlen = htonl(clen);
        std::vector<unsigned char> len4(
            reinterpret_cast<unsigned char*>(&nlen),
            reinterpret_cast<unsigned char*>(&nlen) + 4
        );
        m_net.SendData(m_clientSock, len4);

        // 3) Ciphertext
        m_net.SendData(m_clientSock, cipher);
    }
    std::cout << "[Server] Saliendo del chat.\n";
}

/**
 * @brief Inicia un chat seguro con recepción y envío en paralelo.
 */
void Server::StartChatLoop() {
    std::thread recvThread([&]() {
        StartReceiveLoop();
        });

    SendEncryptedMessageLoop();

    if (recvThread.joinable())
        recvThread.join();
}
