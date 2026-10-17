/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Chave privada protegida por frase secreta (AES-256 derivada com SHA1PRNG) e conferencia com o certificado. */
public class ChaveService {

    // Gera a chave AES de 256 bits a partir de uma semente usando SHA1PRNG.
    // E a mesma derivacao usada para a frase secreta da chave privada e para
    // a semente que vem dentro dos envelopes digitais da pasta segura.
    public SecretKey gerarChaveAES(byte[] semente) throws Exception {

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(semente);

        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256, random);

        return gerador.generateKey();
    }

    public PrivateKey carregarChavePrivada(
            String caminho, String fraseSecreta) throws Exception {

        byte[] dadosCriptografados =
                Files.readAllBytes(Path.of(caminho));

        return carregarChavePrivada(dadosCriptografados, fraseSecreta);
    }

    // Recupera a chave privada a partir dos bytes criptografados
    // (usado tanto para o arquivo .key quanto para o BLOB guardado no Chaveiro).
    public PrivateKey carregarChavePrivada(
            byte[] dadosCriptografados, String fraseSecreta) throws Exception {

        SecretKey chaveAES = gerarChaveAES(
                fraseSecreta.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, chaveAES);

        byte[] dadosDescriptografados =
                cipher.doFinal(dadosCriptografados);

        String chavePem = new String(
                dadosDescriptografados,
                StandardCharsets.US_ASCII
        );

        // O que foi decriptado e um PEM (PKCS8): tira os cabecalhos e decodifica o Base64.
        String chaveBase64 = chavePem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] chavePKCS8 =
                Base64.getDecoder().decode(chaveBase64);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePrivate(
                new PKCS8EncodedKeySpec(chavePKCS8)
        );
    }

    // Verifica se a chave privada corresponde ao certificado assinando um
    // array aleatorio e conferindo a assinatura com a chave publica.
    // Cadastro e consulta usam 10240 bytes; o logView usa 2048 bytes.
    public boolean validarParDeChaves(
            PrivateKey chavePrivada,
            X509Certificate certificado,
            int tamanhoArray) throws Exception {

        byte[] dados = new byte[tamanhoArray];

        SecureRandom random = new SecureRandom();
        random.nextBytes(dados);

        Signature assinador =
                Signature.getInstance("SHA256withRSA");

        assinador.initSign(chavePrivada);
        assinador.update(dados);

        byte[] assinatura = assinador.sign();

        Signature verificador =
                Signature.getInstance("SHA256withRSA");

        verificador.initVerify(certificado.getPublicKey());
        verificador.update(dados);

        return verificador.verify(assinatura);
    }

    public boolean validarParDeChaves(
            PrivateKey chavePrivada,
            X509Certificate certificado) throws Exception {

        return validarParDeChaves(chavePrivada, certificado, 10240);
    }
}
