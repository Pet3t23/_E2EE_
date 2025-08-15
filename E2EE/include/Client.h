#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"
#include "Prerequisites.h"

/**
 * @class Client
 * @brief Clase que representa un cliente capaz de conectarse a un servidor,
 *        intercambiar claves y enviar/recibir mensajes cifrados.
 *
 * Esta clase utiliza NetworkHelper para la comunicación de red y CryptoHelper
 * para el manejo de cifrado RSA/AES.
 */
class Client {
public:
    /**
     * @brief Constructor por defecto.
     */
    Client() = default;

    /**
     * @brief Constructor que inicializa los datos de conexión.
     * @param ip Dirección IP del servidor.
     * @param port Puerto de conexión.
     */
    Client(const std::string& ip, int port);

    /**
     * @brief Destructor.
     */
    ~Client();

    /**
     * @brief Establece conexión con el servidor.
     * @return true si la conexión fue exitosa, false en caso contrario.
     */
    bool Connect();

    /**
     * @brief Intercambia claves públicas con el servidor.
     *
     * Debe llamarse después de Connect() y antes de enviar mensajes cifrados.
     */
    void ExchangeKeys();

    /**
     * @brief Cifra la clave AES con la clave pública del servidor y la envía.
     *
     * Debe llamarse después de ExchangeKeys().
     */
    void SendAESKeyEncrypted();

    /**
     * @brief Cifra un mensaje con AES y lo envía al servidor.
     * @param message Texto en claro a cifrar y enviar.
     */
    void SendEncryptedMessage(const std::string& message);

    /**
     * @brief Inicia un bucle para enviar mensajes cifrados de manera continua.
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Inicia un bucle de chat interactivo con el servidor.
     */
    void StartChatLoop();

    /**
     * @brief Inicia un bucle para recibir y mostrar mensajes del servidor.
     */
    void StartReceiveLoop();

private:
    std::string m_ip;        ///< Dirección IP del servidor.
    int m_port;              ///< Puerto de conexión.
    SOCKET m_serverSock;     ///< Socket de conexión con el servidor.
    NetworkHelper m_net;     ///< Objeto para manejo de operaciones de red.
    CryptoHelper m_crypto;   ///< Objeto para manejo de operaciones criptográficas.
};
