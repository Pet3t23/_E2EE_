#pragma once
#include "Prerequisites.h"
#include "openssl\rsa.h"
#include "openssl\aes.h"

/**
 * @class CryptoHelper
 * @brief Clase auxiliar para manejo de operaciones criptográficas con RSA y AES.
 *
 * Esta clase permite generar claves RSA/AES, intercambiar claves públicas
 * y realizar cifrado/descifrado de mensajes.
 */
class CryptoHelper {
public:
    /**
     * @brief Constructor por defecto.
     *
     * Inicializa los punteros de claves en nullptr.
     */
    CryptoHelper();

    /**
     * @brief Destructor.
     *
     * Libera la memoria asociada a las claves generadas o cargadas.
     */
    ~CryptoHelper();

    // =============================
    //           RSA
    // =============================

    /**
     * @brief Genera un nuevo par de claves RSA de 2048 bits.
     */
    void GenerateRSAKeys();

    /**
     * @brief Devuelve la clave pública en formato PEM como cadena de texto.
     * @return std::string con la clave pública.
     */
    std::string GetPublicKeyString() const;

    /**
     * @brief Carga la clave pública del peer desde un string en formato PEM.
     * @param pemKey Clave pública en formato PEM.
     */
    void LoadPeerPublicKey(const std::string& pemKey);

    // =============================
    //           AES
    // =============================

    /**
     * @brief Genera una clave AES-256 (32 bytes aleatorios).
     */
    void GenerateAESKey();

    /**
     * @brief Cifra la clave AES con la clave pública del peer usando RSA.
     * @return Vector de bytes con la clave AES cifrada.
     */
    std::vector<unsigned char> EncryptAESKeyWithPeer();

    /**
     * @brief Descifra la clave AES enviada por el cliente.
     * @param encryptedKey Vector con la clave AES cifrada.
     */
    void DecryptAESKey(const std::vector<unsigned char>& encryptedKey);

    /**
     * @brief Cifra un mensaje usando AES-256 en modo CBC.
     * @param plaintext Texto plano a cifrar.
     * @param outIV Vector donde se almacenará el IV usado en el cifrado.
     * @return Vector de bytes con el texto cifrado.
     */
    std::vector<unsigned char> AESEncrypt(const std::string& plaintext, std::vector<unsigned char>& outIV);

    /**
     * @brief Descifra un mensaje cifrado con AES-256 en modo CBC.
     * @param ciphertext Vector con el texto cifrado.
     * @param iv Vector con el IV usado en el cifrado.
     * @return Texto plano original.
     */
    std::string AESDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& iv);

private:
    RSA* rsaKeyPair;           ///< Par de claves RSA propias.
    RSA* peerPublicKey;        ///< Clave pública del peer.
    unsigned char aesKey[32];  ///< Clave AES-256 (32 bytes).
};
