/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Operacoes criptograficas sobre os meta-arquivos da pasta segura
 * (.env / .shr, .enc e .asd), seguindo o detalhamento do professor:
 *   envelope digital : RSA/ECB/PKCS1Padding protege a semente;
 *   chave simetrica  : AES-256 gerada com SHA1PRNG a partir da semente;
 *   criptograma      : AES/ECB/PKCS5Padding;
 *   assinatura       : SHA1withRSA sobre o conteudo em texto plano.
 * Esses algoritmos sao os exigidos para compatibilidade com os arquivos
 * de teste; nao devem ser trocados por alternativas mais modernas.
 */
public class ArquivoProtegidoService {

    private final ChaveService chaves = new ChaveService();

    // Abre o envelope digital com a chave privada do destinatario e
    // devolve a semente usada para gerar a chave AES.
    public byte[] abrirEnvelope(Path envelope, PrivateKey chavePrivada) throws Exception {

        byte[] conteudo = Files.readAllBytes(envelope);

        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, chavePrivada);

        return rsa.doFinal(conteudo);
    }

    // Decripta o criptograma (.enc) com a chave AES derivada da semente.
    public byte[] decriptar(Path criptograma, byte[] semente) throws Exception {

        SecretKey chaveAES = chaves.gerarChaveAES(semente);

        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, chaveAES);

        return aes.doFinal(Files.readAllBytes(criptograma));
    }

    // Confere integridade e autenticidade: a assinatura (.asd) deve ter sido
    // produzida sobre o texto plano com a chave privada do dono do arquivo.
    public boolean verificarAssinatura(byte[] textoPlano, Path assinatura,
                                       PublicKey chavePublicaDoDono) throws Exception {

        byte[] bytesAssinatura = Files.readAllBytes(assinatura);

        Signature verificador = Signature.getInstance("SHA1withRSA");
        verificador.initVerify(chavePublicaDoDono);
        verificador.update(textoPlano);

        return verificador.verify(bytesAssinatura);
    }
}
