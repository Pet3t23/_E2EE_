#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"
#include "Prerequisites.h"

/**
 * @class Server
 * @brief Clase que representa un servidor capaz de aceptar clientes,
 *        intercambiar claves y enviar/recibir mensajes cifrados.
 *
 * Utiliza NetworkHelper para la gesti�n de conexiones de red
 * y CryptoHelper para las operaciones de cifrado y descifrado.
 */
class Server {
public:
    /**
     * @brief Constructor por defecto.
     */
    Server() = default;

    /**
     * @brief Constructor que inicializa el puerto del servidor.
     * @param port Puerto TCP en el que se ejecutar� el servidor.
     */
    Server(int port);

    /**
     * @brief Destructor.
     *
     * Libera recursos y detiene hilos de recepci�n si est�n activos.
     */
    ~Server();

    /**
     * @brief Inicia el servidor en el puerto especificado.
     * @return true si el servidor se inicializ� correctamente, false si hubo error.
     */
    bool Start();

    /**
     * @brief Espera la conexi�n de un cliente e intercambia claves p�blicas.
     *
     * Este m�todo debe llamarse despu�s de Start().
     */
    void WaitForClient();

    /**
     * @brief Recibe un mensaje cifrado del cliente, lo descifra y lo imprime por consola.
     */
    void ReceiveEncryptedMessage();

    /**
     * @brief Inicia un bucle para recibir mensajes cifrados de manera continua.
     */
    void StartReceiveLoop();

    /**
     * @brief Inicia un bucle para enviar mensajes cifrados de manera continua.
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Inicia un bucle de chat interactivo con el cliente.
     */
    void StartChatLoop();

private:
    int m_port;                       ///< Puerto de escucha del servidor.
    SOCKET m_clientSock;               ///< Socket del cliente conectado.
    NetworkHelper m_net;               ///< Objeto para gesti�n de red.
    CryptoHelper m_crypto;             ///< Objeto para cifrado/descifrado.
    std::thread m_rxThread;            ///< Hilo para recepci�n de mensajes.
    std::atomic<bool> m_running{ false };///< Estado de ejecuci�n del servidor.
};
