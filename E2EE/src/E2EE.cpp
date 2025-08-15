#include "Prerequisites.h"
#include "Server.h"
#include "Client.h"

/**
 * @brief Funci�n auxiliar para ejecutar el modo servidor.
 *
 * @param port Puerto TCP en el que el servidor escuchar� conexiones.
 *
 * Inicia un servidor, espera la conexi�n de un cliente, realiza el intercambio
 * de claves y comienza un chat cifrado en paralelo.
 */
static void runServer(int port) {
    Server s(port);
    if (!s.Start()) {
        std::cerr << "[Main] No se pudo iniciar el servidor.\n";
        return;
    }
    s.WaitForClient();  // Intercambio de claves
    s.StartChatLoop();  // Comunicaci�n bidireccional cifrada
}

/**
 * @brief Funci�n auxiliar para ejecutar el modo cliente.
 *
 * @param ip Direcci�n IP del servidor al que conectarse.
 * @param port Puerto TCP del servidor.
 *
 * Conecta al servidor, intercambia claves, env�a la clave AES cifrada y
 * comienza un chat cifrado en paralelo.
 */
static void runClient(const std::string& ip, int port) {
    Client c(ip, port);
    if (!c.Connect()) {
        std::cerr << "[Main] No se pudo conectar.\n";
        return;
    }

    c.ExchangeKeys();
    c.SendAESKeyEncrypted();

    // Comunicaci�n en paralelo
    c.StartChatLoop();
}

/**
 * @brief Funci�n principal del programa.
 *
 * @param argc N�mero de argumentos.
 * @param argv Array de argumentos.
 * @return int C�digo de salida (0 si es correcto, 1 si hay error de uso).
 *
 * Uso esperado:
 * - Servidor: `E2EE server <puerto>`
 * - Cliente:  `E2EE client <ip> <puerto>`
 *
 * Si no se pasan argumentos, solicitar� los datos por consola.
 */
int main(int argc, char** argv) {
    std::string mode, ip;
    int port = 0;

    if (argc >= 2) {
        mode = argv[1];
        if (mode == "server") {
            port = (argc >= 3) ? std::stoi(argv[2]) : 12345;
        }
        else if (mode == "client") {
            if (argc < 4) {
                std::cerr << "Uso: E2EE client <ip> <port>\n";
                return 1;
            }
            ip = argv[2];
            port = std::stoi(argv[3]);
        }
        else {
            std::cerr << "Modo no reconocido. Usa: server | client\n";
            return 1;
        }
    }
    else {
        std::cout << "Modo (server/client): ";
        std::cin >> mode;
        if (mode == "server") {
            std::cout << "Puerto: ";
            std::cin >> port;
        }
        else if (mode == "client") {
            std::cout << "IP: ";
            std::cin >> ip;
            std::cout << "Puerto: ";
            std::cin >> port;
        }
        else {
            std::cerr << "Modo no reconocido.\n";
            return 1;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    if (mode == "server") runServer(port);
    else runClient(ip, port);

    return 0;
}
