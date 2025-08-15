#pragma once
#include "Prerequisites.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

/**
 * @class NetworkHelper
 * @brief Clase auxiliar para la gestión de conexiones y transmisión de datos mediante sockets TCP.
 *
 * Proporciona métodos para inicializar un servidor, aceptar clientes,
 * conectarse como cliente, y enviar/recibir datos en formato texto o binario.
 */
class NetworkHelper {
public:
    /**
     * @brief Constructor por defecto.
     *
     * Inicializa las variables internas y, si es necesario, la librería Winsock.
     */
    NetworkHelper();

    /**
     * @brief Destructor.
     *
     * Libera recursos y cierra la librería Winsock si estaba inicializada.
     */
    ~NetworkHelper();

    // =============================
    //         Modo servidor
    // =============================

    /**
     * @brief Inicia un socket servidor en el puerto indicado y lo deja en modo escucha.
     * @param port Puerto TCP para escuchar conexiones entrantes.
     * @return true si el servidor se inicia correctamente, false si ocurre un error.
     */
    bool StartServer(int port);

    /**
     * @brief Espera y acepta un cliente entrante.
     * @return SOCKET del cliente aceptado o INVALID_SOCKET si falla.
     */
    SOCKET AcceptClient();

    // =============================
    //         Modo cliente
    // =============================

    /**
     * @brief Conecta al servidor especificado por IP y puerto.
     * @param ip Dirección IP del servidor.
     * @param port Puerto del servidor.
     * @return true si la conexión fue exitosa, false en caso contrario.
     */
    bool ConnectToServer(const std::string& ip, int port);

    // =============================
    //    Envío y recepción de datos
    // =============================

    /**
     * @brief Envía una cadena de texto por el socket.
     * @param socket Socket conectado.
     * @param data Cadena de texto a enviar.
     * @return true si el envío fue exitoso, false en caso contrario.
     */
    bool SendData(SOCKET socket, const std::string& data);

    /**
     * @brief Envía datos binarios (ej. claves AES/RSA) por el socket.
     * @param socket Socket conectado.
     * @param data Vector de bytes a enviar.
     * @return true si el envío fue exitoso, false en caso contrario.
     */
    bool SendData(SOCKET socket, const std::vector<unsigned char>& data);

    /**
     * @brief Recibe una cadena de texto desde el socket.
     * @param socket Socket conectado.
     * @return Cadena recibida.
     */
    std::string ReceiveData(SOCKET socket);

    /**
     * @brief Recibe datos binarios desde el socket.
     * @param socket Socket conectado.
     * @param size Tamaño esperado de los datos (opcional, 0 para recibir todo).
     * @return Vector de bytes recibidos.
     */
    std::vector<unsigned char> ReceiveDataBinary(SOCKET socket, int size = 0);

    /**
     * @brief Cierra un socket.
     * @param socket Socket a cerrar.
     */
    void close(SOCKET socket);

    /**
     * @brief Envía todos los bytes indicados, asegurando que el envío sea completo.
     * @param s Socket conectado.
     * @param data Puntero a los datos a enviar.
     * @param len Longitud en bytes a enviar.
     * @return true si el envío fue exitoso, false en caso contrario.
     */
    bool SendAll(SOCKET s, const unsigned char* data, int len);

    /**
     * @brief Recibe exactamente la cantidad de bytes indicada.
     * @param s Socket conectado.
     * @param out Puntero al buffer donde se almacenarán los datos.
     * @param len Longitud exacta a recibir.
     * @return true si la recepción fue exitosa, false en caso contrario.
     */
    bool ReceiveExact(SOCKET s, unsigned char* out, int len);

public:
    SOCKET m_serverSocket = -1; ///< Socket del servidor en modo escucha.

private:
    bool m_initialized; ///< Indica si Winsock fue inicializado correctamente.
};
