/**
 * ============================================================
 * 🔐 CryptoUtil.js
 * ------------------------------------------------------------
 * Biblioteca criptográfica modular da Metafree.
 * 
 * Oferece:
 *  - Criptografia e descriptografia AES-GCM com PBKDF2.
 *  - Assinatura e verificação HMAC-SHA256.
 *  - Derivação de chave autenticadora para uso com bcrypt/PHP.
 * 
 * Compatível com: Navegador (WebCrypto API) e Node.js.
 * 
 * @version 1.0.0
 * @license MIT
 * @author 
 *   Metafree © 2025
 *   Desenvolvido com apoio de ChatGPT (OpenAI GPT-5)
 * ============================================================
 */

// ============================================================
// 🔧 CONFIGURAÇÕES GLOBAIS
// ============================================================

/**
 * Sal constante usado na derivação de chave de autenticação.
 * Essa string define a versão e garante consistência entre cliente/servidor.
 * ⚠️ Alterar apenas em versões futuras, pois invalida hashes anteriores.
 */
const SALT_AUTH = "Metafree::Auth.v1";

/**
 * Prefixo usado para derivar chaves únicas por usuário/dado.
 * Recomenda-se usar SALT_DATA_PREFIX + userId ou + domínio lógico.
 */
const SALT_DATA_PREFIX = "Metafree::Data::";

/**
 * Número de iterações PBKDF2 (padrão moderno: >= 100k).
 */
const PBKDF2_ITER = 100_000;

/**
 * Algoritmo simétrico usado para criptografia.
 */
const AES_ALGO = { name: "AES-GCM", length: 256 };

/**
 * Configuração geral (utilizada internamente).
 */
const CRYPTO_CONFIG = {
    saltLength: 16,
    ivLength: 12,
    iterations: PBKDF2_ITER,
    hash: "SHA-256",
    keyLength: 256,
    aesAlgorithm: AES_ALGO.name,
    derivationAlgorithm: "PBKDF2",
};

// ============================================================
// 🧩 FUNÇÕES INTERNAS
// ============================================================

/**
 * Importa a senha bruta como material de chave para PBKDF2.
 * @param {string} password Senha fornecida pelo usuário.
 * @returns {Promise<CryptoKey>} Material de chave PBKDF2.
 */
async function importPassword(password) {
    const encoder = new TextEncoder();
    const passBuffer = encoder.encode(password);
    return crypto.subtle.importKey(
        "raw",
        passBuffer,
        CRYPTO_CONFIG.derivationAlgorithm,
        false,
        ["deriveBits", "deriveKey"]
    );
}

/**
 * Deriva chaves simétricas AES e HMAC a partir de uma senha.
 * @param {string} password Senha de base.
 * @param {Uint8Array|null} salt Opcional: sal fixo ou aleatório.
 * @returns {Promise<{salt: Uint8Array, aesKey: CryptoKey, hmacKey: CryptoKey}>}
 */
async function deriveKeys(password, salt = null) {
    const saltBuf = salt
        ? salt instanceof Uint8Array
            ? salt
            : Uint8Array.from(salt)
        : crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.saltLength));

    const keyMaterial = await importPassword(password);

    const aesKey = await crypto.subtle.deriveKey(
        {
            name: CRYPTO_CONFIG.derivationAlgorithm,
            salt: saltBuf,
            iterations: CRYPTO_CONFIG.iterations,
            hash: CRYPTO_CONFIG.hash,
        },
        keyMaterial,
        AES_ALGO,
        false,
        ["encrypt", "decrypt"]
    );

    const hmacKey = await crypto.subtle.deriveKey(
        {
            name: CRYPTO_CONFIG.derivationAlgorithm,
            salt: saltBuf,
            iterations: CRYPTO_CONFIG.iterations,
            hash: CRYPTO_CONFIG.hash,
        },
        keyMaterial,
        { name: "HMAC", hash: CRYPTO_CONFIG.hash, length: CRYPTO_CONFIG.keyLength },
        false,
        ["sign", "verify"]
    );

    return { salt: saltBuf, aesKey, hmacKey };
}

// ============================================================
// 🔒 CRIPTOGRAFIA E DESCRIPTOGRAFIA
// ============================================================

/**
 * Criptografa texto com AES-GCM e autenticação HMAC.
 * @param {string} password Senha base de derivação.
 * @param {string} plaintext Texto em claro a ser criptografado.
 * @returns {Promise<string>} Texto criptografado em Base64.
 */
async function encryptData(password, plaintext) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const { salt, aesKey, hmacKey } = await deriveKeys(password);
    const iv = crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.ivLength));

    const ciphertext = await crypto.subtle.encrypt({ name: AES_ALGO.name, iv }, aesKey, data);

    const encryptedBlob = new Uint8Array(
        salt.byteLength + iv.byteLength + ciphertext.byteLength
    );
    encryptedBlob.set(salt, 0);
    encryptedBlob.set(iv, salt.byteLength);
    encryptedBlob.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);

    const signature = await crypto.subtle.sign("HMAC", hmacKey, encryptedBlob);

    const finalBlob = new Uint8Array(encryptedBlob.byteLength + signature.byteLength);
    finalBlob.set(encryptedBlob, 0);
    finalBlob.set(new Uint8Array(signature), encryptedBlob.byteLength);

    return btoa(String.fromCharCode(...finalBlob));
}

/**
 * Descriptografa texto em Base64 previamente cifrado com encryptData().
 * @param {string} password Senha original usada na criptografia.
 * @param {string} base64Data Dados criptografados em Base64.
 * @returns {Promise<string>} Texto em claro (UTF-8).
 */
async function decryptData(password, base64Data) {
    const allBytes = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));

    const salt = allBytes.slice(0, CRYPTO_CONFIG.saltLength);
    const iv = allBytes.slice(CRYPTO_CONFIG.saltLength, CRYPTO_CONFIG.saltLength + CRYPTO_CONFIG.ivLength);
    const signature = allBytes.slice(allBytes.byteLength - 32);
    const encryptedData = allBytes.slice(0, allBytes.byteLength - 32);

    const { aesKey, hmacKey } = await deriveKeys(password, salt);
    const valid = await crypto.subtle.verify("HMAC", hmacKey, signature, encryptedData);
    if (!valid) throw new Error("Assinatura HMAC inválida — dados corrompidos.");

    const ciphertext = encryptedData.slice(CRYPTO_CONFIG.saltLength + CRYPTO_CONFIG.ivLength);
    const decrypted = await crypto.subtle.decrypt({ name: AES_ALGO.name, iv }, aesKey, ciphertext);

    return new TextDecoder().decode(decrypted);
}

// ============================================================
// 🧾 ASSINATURA E VERIFICAÇÃO BINÁRIA
// ============================================================

/**
 * Gera assinatura HMAC-SHA256 de um binário (ex: PDF, imagem).
 * @param {string} password Senha base.
 * @param {ArrayBuffer|Blob} binaryData Dados a assinar.
 * @returns {Promise<{salt: string, signature: string}>} Assinatura Base64.
 */
async function signBinary(password, binaryData) {
    const buffer =
        binaryData instanceof ArrayBuffer
            ? binaryData
            : await binaryData.arrayBuffer();

    const { hmacKey, salt } = await deriveKeys(password);
    const signature = await crypto.subtle.sign("HMAC", hmacKey, buffer);

    return {
        salt: btoa(String.fromCharCode(...salt)),
        signature: btoa(String.fromCharCode(...new Uint8Array(signature))),
    };
}

/**
 * Verifica assinatura HMAC-SHA256 de um binário.
 * @param {string} password Senha base.
 * @param {ArrayBuffer|Blob} binaryData Dados originais.
 * @param {string} base64Salt Sal usado na assinatura.
 * @param {string} base64Signature Assinatura gerada.
 * @returns {Promise<boolean>} true se válido, false se adulterado.
 */
async function verifyBinary(password, binaryData, base64Salt, base64Signature) {
    const buffer =
        binaryData instanceof ArrayBuffer
            ? binaryData
            : await binaryData.arrayBuffer();

    const salt = Uint8Array.from(atob(base64Salt), (c) => c.charCodeAt(0));
    const signature = Uint8Array.from(atob(base64Signature), (c) => c.charCodeAt(0));

    const { hmacKey } = await deriveKeys(password, salt);
    return crypto.subtle.verify("HMAC", hmacKey, signature, buffer);
}

// ============================================================
// 🔑 DERIVAÇÃO DE CHAVE DE AUTENTICAÇÃO
// ============================================================

/**
 * Deriva uma chave determinística (base64) para autenticação.
 * Usada para armazenar no servidor via bcrypt ou hash similar.
 * @param {string} password Senha do usuário.
 * @param {string} [constantSalt=SALT_AUTH] Sal lógico constante.
 * @returns {Promise<string>} Chave derivada em Base64.
 */
async function deriveAuthKey(password, constantSalt = SALT_AUTH) {
    const encoder = new TextEncoder();
    const salt = encoder.encode(constantSalt);

    const keyMaterial = await importPassword(password);
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: CRYPTO_CONFIG.derivationAlgorithm,
            salt,
            iterations: CRYPTO_CONFIG.iterations,
            hash: CRYPTO_CONFIG.hash,
        },
        keyMaterial,
        CRYPTO_CONFIG.keyLength
    );

    const hashArray = Array.from(new Uint8Array(derivedBits));
    return btoa(String.fromCharCode(...hashArray));
}

// ============================================================
// 📦 EXPORTAÇÃO GLOBAL / MODULAR
// ============================================================

const CryptoUtil = {
    CRYPTO_CONFIG,
    SALT_AUTH,
    SALT_DATA_PREFIX,
    PBKDF2_ITER,
    AES_ALGO,
    importPassword,
    deriveKeys,
    encryptData,
    decryptData,
    signBinary,
    verifyBinary,
    deriveAuthKey,
};

// Compatibilidade com Browser e Node.js
if (typeof window !== "undefined") window.CryptoUtil = CryptoUtil;
if (typeof module !== "undefined") module.exports = CryptoUtil;

/**
 * ============================================================
 * 📘 Exemplo de uso:
 * ------------------------------------------------------------
 * const secret = await CryptoUtil.encryptData("senha123", "texto confidencial");
 * const plain  = await CryptoUtil.decryptData("senha123", secret);
 *
 * const authKey = await CryptoUtil.deriveAuthKey("senha123");
 * console.log("AuthKey:", authKey);
 * ============================================================
 */
