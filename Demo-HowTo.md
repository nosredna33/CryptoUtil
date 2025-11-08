# Como usar 

O **`demo_crypto.html`** é um arquivo didático completo — pronto para testar.

Ele demonstra **todo o ciclo criptográfico**:

* Derivação da chave de autenticação (bcrypt compatível)
* Derivação da chave simétrica exclusiva por ID
* Criptografia e descriptografia local (AES-256-GCM)
* Assinatura e verificação digital (ECDSA-P256)

---

## 🧪 `demo_crypto.html`

[`demo_crypto.html`](https://github.com/nosredna33/CryptoUtil/blob/main/Demo_CryptoUtil.html)

---

### ⚙️ Como usar

1. Coloque este arquivo na mesma pasta de `CryptoUtil.js`.
2. Abra no navegador (nenhum servidor necessário).
3. Clique em **Executar Teste Completo**.
4. Observe no console e no `<pre>` o fluxo completo de:

   * Derivação das chaves
   * Criptografia local
   * Descriptografia
   * Assinatura e verificação

---

### 🧭 Objetivo didático

Este `demo_crypto.html` ilustra visualmente o que a [**Metafree Blockchain**](https://metafree.com.br/) faz em escala:

* Cada operação de registro (dados, documentos, evidências) é cifrada localmente;
* Gera-se uma **prova verificável** (assinatura digital + hash de integridade);
* Esses blocos cifrados são armazenados e validados dentro do **Cofre de Evidências**.

