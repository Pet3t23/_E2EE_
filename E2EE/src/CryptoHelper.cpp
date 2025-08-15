#include "CryptoHelper.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/evp.h"

/**
 * @brief Constructor por defecto.
 *
 * Inicializa punteros de claves en nullptr y la clave AES en cero.
 */
CryptoHelper::CryptoHelper()
    : rsaKeyPair(nullptr), peerPublicKey(nullptr) {
    std::memset(&aesKey, 0, sizeof(aesKey));
}

/**
 * @brief Destructor.
 *
 * Libera memoria de las claves RSA generadas o cargadas.
 */
CryptoHelper::~CryptoHelper() {
    if (rsaKeyPair) {
        RSA_free(rsaKeyPair);
    }
    if (peerPublicKey) {
        RSA_free(peerPublicKey);
    }
}

/**
 * @brief Genera un nuevo par de claves RSA de 2048 bits.
 */
void CryptoHelper::GenerateRSAKeys() {
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    rsaKeyPair = RSA_new();
    RSA_generate_key_ex(rsaKeyPair, 2048, bn, nullptr);
    BN_free(bn);
}

/**
 * @brief Obtiene la clave pública en formato PEM como string.
 * @return std::string con la clave pública.
 */
std::string CryptoHelper::GetPublicKeyString() const {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsaKeyPair);
    char* buffer = nullptr;
    size_t length = BIO_get_mem_data(bio, &buffer);
    std::string publicKey(buffer, length);
    BIO_free(bio);
    return publicKey;
}

/**
 * @brief Carga la clave pública del peer desde un string PEM.
 * @param pemKey Clave pública en formato PEM.
 * @throws std::runtime_error si la clave no se puede cargar.
 */
void CryptoHelper::LoadPeerPublicKey(const std::string& pemKey) {
    BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
    peerPublicKey = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!peerPublicKey) {
        throw std::runtime_error("Failed to load peer public key: "
            + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
}

/**
 * @brief Genera una clave AES-256 (32 bytes aleatorios).
 */
void CryptoHelper::GenerateAESKey() {
    RAND_bytes(aesKey, sizeof(aesKey));
}

/**
 * @brief Cifra la clave AES con la clave pública del peer usando RSA-OAEP.
 * @return Vector de bytes con la clave cifrada.
 * @throws std::runtime_error si la clave pública del peer no está cargada.
 */
std::vector<unsigned char> CryptoHelper::EncryptAESKeyWithPeer() {
    if (!peerPublicKey) {
        throw std::runtime_error("Peer public key is not loaded.");
    }
    std::vector<unsigned char> encryptedKey(256);
    int result = RSA_public_encrypt(sizeof(aesKey),
        aesKey,
        encryptedKey.data(),
        peerPublicKey,
        RSA_PKCS1_OAEP_PADDING);
    encryptedKey.resize(result);

    return encryptedKey;
}

/**
 * @brief Descifra la clave AES enviada por el cliente usando la clave privada RSA.
 * @param encryptedKey Vector con la clave cifrada.
 */
void CryptoHelper::DecryptAESKey(const std::vector<unsigned char>& encryptedKey) {
    RSA_private_decrypt(encryptedKey.size(),
        encryptedKey.data(),
        aesKey,
        rsaKeyPair,
        RSA_PKCS1_OAEP_PADDING);
}

/**
 * @brief Cifra un mensaje con AES-256-CBC.
 * @param plaintext Texto en claro a cifrar.
 * @param outIV Vector donde se almacenará el IV generado.
 * @return Vector de bytes con el texto cifrado.
 */
std::vector<unsigned char> CryptoHelper::AESEncrypt(const std::string& plaintext,
    std::vector<unsigned char>& outIV) {
    outIV.resize(AES_BLOCK_SIZE);
    RAND_bytes(outIV.data(), AES_BLOCK_SIZE);

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    std::vector<unsigned char> out(plaintext.size() + AES_BLOCK_SIZE); // +pad
    int outlen1 = 0, outlen2 = 0;

    EVP_EncryptInit_ex(ctx, cipher, nullptr, aesKey, outIV.data());
    EVP_EncryptUpdate(ctx,
        out.data(), &outlen1,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        static_cast<int>(plaintext.size()));
    EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2);

    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

/**
 * @brief Descifra un mensaje cifrado con AES-256-CBC.
 * @param ciphertext Vector de bytes cifrado.
 * @param iv Vector con el IV usado en el cifrado.
 * @return Texto plano descifrado o cadena vacía si hay error.
 */
std::string CryptoHelper::AESDecrypt(const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& iv) {
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    std::vector<unsigned char> out(ciphertext.size());
    int outlen1 = 0, outlen2 = 0;

    EVP_DecryptInit_ex(ctx, cipher, nullptr, aesKey, iv.data());
    EVP_DecryptUpdate(ctx,
        out.data(), &outlen1,
        ciphertext.data(),
        static_cast<int>(ciphertext.size()));
    if (EVP_DecryptFinal_ex(ctx, out.data() + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // padding/key/iv incorrectos
    }

    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(out.data()), out.size());
}
