#include "Client.h"

/**
 * @brief Constructor que inicializa IP, puerto y genera claves RSA/AES.
 * @param ip Direcci�n IP del servidor.
 * @param port Puerto del servidor.
 */
Client::Client(const std::string& ip, int port)
    : m_ip(ip), m_port(port), m_serverSock(INVALID_SOCKET) {
    // Genera par de claves RSA al instanciar
    m_crypto.GenerateRSAKeys();
    // Genera la clave AES que se usar� para cifrar mensajes
    m_crypto.GenerateAESKey();
}

/**
 * @brief Destructor. Cierra el socket si est� activo.
 */
Client::~Client() {
    if (m_serverSock != INVALID_SOCKET) {
        m_net.close(m_serverSock);
    }
}

/**
 * @brief Establece conexi�n con el servidor.
 * @return true si la conexi�n fue exitosa, false en caso contrario.
 */
bool Client::Connect() {
    std::cout << "[Client] Conectando al servidor " << m_ip << ":" << m_port << "...\n";
    bool connected = m_net.ConnectToServer(m_ip, m_port);
    if (connected) {
        m_serverSock = m_net.m_serverSocket; // Guardar el socket una vez conectado
        std::cout << "[Client] Conexi�n establecida.\n";
    }
    else {
        std::cerr << "[Client] Error al conectar.\n";
    }
    return connected;
}

/**
 * @brief Intercambia claves p�blicas con el servidor.
 *
 * Recibe primero la clave p�blica del servidor y luego env�a la propia.
 */
void Client::ExchangeKeys() {
    // 1. Recibe la clave p�blica del servidor
    std::string serverPubKey = m_net.ReceiveData(m_serverSock);
    m_crypto.LoadPeerPublicKey(serverPubKey);
    std::cout << "[Client] Clave p�blica del servidor recibida.\n";

    // 2. Env�a la clave p�blica del cliente
    std::string clientPubKey = m_crypto.GetPublicKeyString();
    m_net.SendData(m_serverSock, clientPubKey);
    std::cout << "[Client] Clave p�blica del cliente enviada.\n";
}

/**
 * @brief Cifra la clave AES con la p�blica del servidor y la env�a.
 */
void Client::SendAESKeyEncrypted() {
    std::vector<unsigned char> encryptedAES = m_crypto.EncryptAESKeyWithPeer();
    m_net.SendData(m_serverSock, encryptedAES);
    std::cout << "[Client] Clave AES cifrada y enviada al servidor.\n";
}

/**
 * @brief Cifra un mensaje con AES y lo env�a al servidor.
 * @param message Texto plano a enviar.
 */
void Client::SendEncryptedMessage(const std::string& message) {
    std::vector<unsigned char> iv;
    auto cipher = m_crypto.AESEncrypt(message, iv);

    // 1) IV (16 bytes)
    m_net.SendData(m_serverSock, iv);

    // 2) Tama�o (4 bytes en big-endian)
    uint32_t clen = static_cast<uint32_t>(cipher.size());
    uint32_t nlen = htonl(clen);
    std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
        reinterpret_cast<unsigned char*>(&nlen) + 4);
    m_net.SendData(m_serverSock, len4);

    // 3) Ciphertext
    m_net.SendData(m_serverSock, cipher);
}

/**
 * @brief Bucle para enviar mensajes cifrados introducidos por el usuario.
 */
void Client::SendEncryptedMessageLoop() {
    std::string msg;
    while (true) {
        std::cout << "Cliente: ";
        std::getline(std::cin, msg);
        if (msg == "/exit") break;

        std::vector<unsigned char> iv;
        auto cipher = m_crypto.AESEncrypt(msg, iv);

        m_net.SendData(m_serverSock, iv);

        uint32_t clen = static_cast<uint32_t>(cipher.size());
        uint32_t nlen = htonl(clen);
        std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
            reinterpret_cast<unsigned char*>(&nlen) + 4);
        m_net.SendData(m_serverSock, len4);

        m_net.SendData(m_serverSock, cipher);
    }
}

/**
 * @brief Bucle que recibe mensajes cifrados, los descifra y los muestra.
 */
void Client::StartReceiveLoop() {
    while (true) {
        // 1) IV (16 bytes)
        auto iv = m_net.ReceiveDataBinary(m_serverSock, 16);
        if (iv.empty()) {
            std::cout << "\n[Client] Conexi�n cerrada por el servidor.\n";
            break;
        }

        // 2) Tama�o (4 bytes)
        auto len4 = m_net.ReceiveDataBinary(m_serverSock, 4);
        if (len4.size() != 4) {
            std::cout << "[Client] Error al recibir tama�o.\n";
            break;
        }
        uint32_t nlen = 0;
        std::memcpy(&nlen, len4.data(), 4);
        uint32_t clen = ntohl(nlen);

        // 3) Ciphertext
        auto cipher = m_net.ReceiveDataBinary(m_serverSock, static_cast<int>(clen));
        if (cipher.empty()) {
            std::cout << "[Client] Error al recibir datos.\n";
            break;
        }

        // 4) Descifrar y mostrar
        std::string plain = m_crypto.AESDecrypt(cipher, iv);
        std::cout << "\n[Servidor]: " << plain << "\nCliente: ";
        std::cout.flush();
    }
    std::cout << "[Client] ReceiveLoop terminado.\n";
}

/**
 * @brief Inicia un bucle de chat con recepci�n y env�o simult�neos.
 */
void Client::StartChatLoop() {
    std::thread recvThread([&]() {
        StartReceiveLoop();
        });

    SendEncryptedMessageLoop();

    if (recvThread.joinable())
        recvThread.join();
}
