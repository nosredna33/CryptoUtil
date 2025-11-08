# CryptoUtil
Uma biblioteca Javascript robusta para oferecer serviços de autenticação, criptografia e assinatura digital para aplicações Web feitas para [Metafree](https://metafree.com.br/).


# Documentação

> **Resumo:** `CryptoUtil.js` é uma biblioteca cliente-side (WebCrypto API) criada para o projeto Metafree.
> Ela fornece derivação de chaves, criptografia (AES-GCM), assinaturas HMAC (HMAC-SHA256) e derivação determinística para autenticação (`kAuth`) — tudo com parâmetros versionáveis, pensados para segurança prática e compatibilidade com o back-end (PHP + bcrypt).

---

# Especificações técnicas

```javascript
/**
 * ============================================================
 * 🧠 SOBRE ESTE ALGORITMO
 * ------------------------------------------------------------
 * O Metafree Core foi desenvolvido com base nas recomendações:
 *
 * - NIST SP 800-132 (Derivação PBKDF2)
 * - NIST SP 800-38D (AES-GCM)
 * - FIPS 186-4 (ECDSA/RSA Assinatura)
 * - RFC 7518 (JSON Web Algorithms)
 *
 * Design motivado pelo princípio:
 * > "A segurança deve ser verificável — não presumida."
 * 
 * O uso de SALT fixo para autenticação garante que a senha
 * do usuário gere sempre a mesma hash derivada para login
 * (permitindo validação bcrypt no servidor), enquanto o
 * SALT prefixado com ID garante exclusividade por registro.
 * 
 * O resultado é uma arquitetura híbrida:
 * - 🔑 Criptografia local (client-side)
 * - 🧾 Autenticação segura (server-side)
 * - 🧱 Base para blockchain de evidências verificáveis
 * ============================================================
 */

```

---


## Objetivos e contexto (por que criamos isto)

1. **Privacidade e “zero-knowledge”** — os dados sensíveis (ex.: nome, CPF, endereço) são cifrados no cliente e o servidor **não** deve ter acesso ao texto claro.
2. **Autenticação segura sem transmitir senha em claro** — o cliente envia uma derivação (`kAuth`) ao servidor; o servidor armazena apenas o `bcrypt(kAuth)` (ou `password_hash` equivalente), não a senha.
3. **Integridade / prova de autenticidade** — cada bloco cifrado carrega HMAC, permitindo detectar adulterações.
4. **Compatibilidade prática** — compatível com WebCrypto no browser; o servidor usa bcrypt para armazenar verificador (PHP `password_hash` / `password_verify`).
5. **Versionamento / manutenção** — parâmetros como `SALT_AUTH` codificam versões para permitir upgrades controlados.

---

## Como chegamos a este algoritmo (racional de projeto)

### Ameaças consideradas

* Roubo do banco (dump): dados cifrados + bcrypt sobre verificador impede obter senhas e dificulta descriptografia dos dados.
* Interceptação de tráfego: protegida por TLS; além disso, a senha nunca é transmitida em claro no fluxo planejado (só `kAuth`).
* Modificação de dados: deter com HMAC sobre o blob cifrado.
* Reuso / colisão de chaves: separar domínio de chaves (auth vs data) evita que autenticação sirva para descriptografar dados.

### Escolhas principais e porquê

* **PBKDF2 (WebCrypto)** — amplamente suportado pelo WebCrypto API, determinístico e suficiente com um número adequado de iterações. Alternativas como Argon2 ou scrypt são melhores contra brute force em geral, mas não estão disponíveis diretamente via WebCrypto sem bibliotecas JS adicionais (e executar Argon2 em JS no browser tem custo CPU muito alto). PBKDF2 com iterações elevadas é um compromisso prático.
* **AES-GCM** — cifragem autenticada padrão, rápida e suportada por WebCrypto. GCM já protege confidencialidade + integridade (mas usamos HMAC também para empacotamento consistente e compatibilidade).
* **HMAC-SHA256** — assinatura de dados tanto para blobs quanto para binários. Simples, seguro e suportado.
* **bcrypt no servidor** — bcrypt/`password_hash()` fornece sal por usuário e work factor; o servidor nunca armazena nem precisa da senha em claro. Armazenamos `bcrypt(kAuth)`.
* **Sal aleatório para dados** — cada blob cifrado tem um salt aleatório anexado, o que impede correlação entre mesmas senhas.
* **Sal fixo (versão) para `kAuth`** — o sal fixo dá um domínio de derivação previsível entre cliente/servidor (`SALT_AUTH = "Metafree::Auth.v1"`). A aleatoriedade / defesa contra rainbow tables fica por conta do bcrypt no servidor (bcrypt gera sal por usuário internamente). O sal fixo serve para *separar* "kAuth" do domínio de cifragem de dados (K_data).

### Resumo da cadeia

* `kAuth = PBKDF2(password, SALT_AUTH, iterations)` → enviado ao servidor → `bcrypt(kAuth)` → armazenado.
* `K_data` derivada com PBKDF2 e **salt aleatório** → AES-GCM cifragem do JSON → blob = salt || iv || ciphertext || hmac.
* `verifyAndDecrypt` valida HMAC e então descriptografa.

---

## Parâmetros e constantes (versões)

* `SALT_AUTH = "Metafree::Auth.v1"` — sal lógico para derivação de autenticação (modifique ao quebrar compatibilidade).
* `SALT_DATA_PREFIX = "Metafree::Data::"` — prefixo quando quiser compor salt por usuário/extrato.
* `PBKDF2_ITER = 100_000` — número de iterações PBKDF2 (ajustável por versão/hardware).
* `AES_ALGO = { name: "AES-GCM", length: 256 }` — algoritmo simétrico.
* `saltLength = 16 (bytes)`, `ivLength = 12 (bytes)` — comprimento do salt/iv usados.

> **Nota:** ajustar `PBKDF2_ITER` para valores maiores ao longo do tempo conforme a CPU evolui; sempre versão (e.g., `Auth.v2`) ao mudar esses parâmetros.

---

## API (funções principais) — uso rápido

> O arquivo exporta `CryptoUtil` (objeto global) com estas funções:

### `CryptoUtil.encryptData(password, plaintext) => Promise<string (base64)>`

* Descrição: cifra `plaintext` com AES-GCM. Retorna um blob Base64 que contém: `salt || iv || ciphertext || signature`.
* Uso:

```js
const ciphertextB64 = await CryptoUtil.encryptData('senha123', JSON.stringify(userData));
```

### `CryptoUtil.decryptData(password, base64Data) => Promise<string>`

* Descrição: valida HMAC e descriptografa. Lança erro se HMAC inválido.
* Uso:

```js
const plain = await CryptoUtil.decryptData('senha123', ciphertextB64);
const obj = JSON.parse(plain);
```

### `CryptoUtil.signBinary(password, binaryData) => Promise<{salt, signature}>`

* Descrição: assina binário (ArrayBuffer ou Blob) com HMAC.
* Uso:

```js
const { salt, signature } = await CryptoUtil.signBinary('senha', fileBlob);
```

### `CryptoUtil.verifyBinary(password, binaryData, base64Salt, base64Signature) => Promise<boolean>`

* Descrição: verifica assinatura HMAC.
* Uso:

```js
const ok = await CryptoUtil.verifyBinary('senha', fileBlob, salt, signature);
```

### `CryptoUtil.deriveAuthKey(password) => Promise<string (base64)>`

* Descrição: deriva um valor determinístico (base64) para autenticação; enviar ao servidor e armazenar `bcrypt(kAuth)`.
* Uso:

```js
const kAuth = await CryptoUtil.deriveAuthKey('senha123');
// enviar kAuth no POST de login/registro
```

---

## Exemplos de integração

### Registro (cliente)

1. Usuário escolhe senha `S` e insere dados `userData`.
2. Cliente:

```js
const saltForData = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
const { ciphertext } = await CryptoUtil.encryptData(S, JSON.stringify(userData)); // salt incluído internamente
const kAuth = await CryptoUtil.deriveAuthKey(S);

const payload = {
  id_unico: uuid,
  apelido,
  email,
  dados_criptografados: ciphertext,
  kAuth // enviado ao servidor para bcrypt
};

fetch('registro_processar.php', { method: 'POST', body: new URLSearchParams({ registro: btoa(JSON.stringify(payload)) }) });
```

### Registro (servidor — PHP)

```php
// $kAuth recebido do cliente
$authHash = password_hash($kAuth, PASSWORD_BCRYPT);
// salvar authHash no campo auth_hash do usuário
```

### Login (cliente)

```js
const kAuth = await CryptoUtil.deriveAuthKey(senha);
fetch('login.php', { method: 'POST', body: new URLSearchParams({ email, kAuth }) });
```

### Login (servidor)

```php
// Recupera auth_hash por email e faz:
if (password_verify($kAuth, $auth_hash)) {
    // ok — cria session
}
```

### Recuperar dados (após login)

* Servidor retorna `dados_criptografados` (o blob Base64).
* Cliente:

```js
const plain = await CryptoUtil.decryptData(senha, dados_criptografados);
const obj = JSON.parse(plain);
```

---

## Formato do blob criptografado (interno)

`finalBlob = salt (N bytes) || iv (12 bytes) || ciphertext || signature (32 bytes HMAC-SHA256)`

* `salt` — necessário para derivar chave AES/HMAC para descriptografia.
* `iv` — nonce AES-GCM.
* `signature` — HMAC do `encryptedBlob` (salt + iv + ciphertext) para detectar qualquer adulteração antes da tentativa de decrypt.

---

## Boas práticas / recomendações operacionais

* **Sempre HTTPS.**
* **Proteja o back-end**: chave privada do CA / certificados em filesystem com permissão restrita; idealmente em HSM/KMS.
* **Use `password_hash` (bcrypt/argon2id)** no servidor; não escreva seu próprio sal de bcrypt.
* **Log de auditoria**: registre eventos sensíveis (login, assinatura PDF, revogação) com timestamp/IP.
* **Rate limit** endpoints de login e CAPTCHAs/lockouts por tentativas.
* **Atualizações/versões**: quando mudar parâmetros PBKDF2/AES/algoritmos, avance a tag do SALT (e suporte migração).
* **Backup do salt**: para cada blob cifrado, o salt está embutido; não perca o blob — sem salt/iv corretos o dado é irrecuperável.

---

## Interoperabilidade e limites

* **WebCrypto**: disponível nos navegadores modernos. Em ambientes sem WebCrypto (navegadores antigos) você precisará de polyfills ou mover a lógica para o servidor (perde-se o zero-knowledge).
* **Texto grande**: AES-GCM + HMAC é adequado; para arquivos grandes (vários MB) considere chunking/streaming.
* **Assinatura jurídica**: HMAC + assinatura interna Metafree CA servem para integridade e prova, mas para validade jurídica formal pode ser necessária ICP-Brasil / gov.br ou assinatura com certificado reconhecido (PKI).

---

## Migração e versionamento

* Para evoluir parâmetros:

  * altere `SALT_AUTH` (e.g., `Auth.v2`) → obrigará usuários a re-registrar ou você pode suportar ambos formatos no servidor (armazenar a versão junto ao `auth_hash`).
  * para dados já cifrados com SALT antigo, mantenha o salt embutido (já está no blob) — descriptografia funciona independente da versão do SALT_AUTH (porque SALT_AUTH não é usado para dados).
  * documente mudanças no `CHANGELOG.md` do repo.

---

## Conclusão

O `CryptoUtil.js` empacota práticas modernas de criptografia aplicáveis a um serviço web no qual:

* **os dados permanecem confidenciais no cliente**,
* **o servidor armazena apenas verificadores seguros**,
* e **a integridade é garantida por HMAC**.
