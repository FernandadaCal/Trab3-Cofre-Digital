/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.io.Console;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/** Teste manual: abre a chave privada do admin com a frase secreta e confere com o certificado. */
public class TesteChave {

    public static void main(String[] args) {

        String caminhoCertificado =
                "arquivos-teste/Keys/admin-x509.crt";

        String caminhoChave =
                "arquivos-teste/Keys/admin-pkcs8-aes.key";

        CertificadoService certificadoService = new CertificadoService();
        ChaveService chaveService = new ChaveService();

        try {
            String fraseSecreta;

            Console console = System.console();

            if (console != null) {
                char[] senha = console.readPassword(
                        "Digite a frase secreta da chave privada: ");

                if (senha == null) {
                    return;
                }

                fraseSecreta = new String(senha);
                java.util.Arrays.fill(senha, '\0');

            } else {
                Scanner scanner = new Scanner(System.in);

                System.out.print(
                        "Digite a frase secreta da chave privada: ");

                fraseSecreta = scanner.nextLine();
            }

            X509Certificate certificado =
                    certificadoService.carregarCertificado(
                            caminhoCertificado
                    );

            certificadoService.validarValidade(certificado);

            System.out.println("Certificado carregado com sucesso!");

            PrivateKey chavePrivada =
                    chaveService.carregarChavePrivada(
                            caminhoChave,
                            fraseSecreta
                    );

            fraseSecreta = null;

            System.out.println("Chave privada recuperada com sucesso!");

            boolean corresponde =
                    chaveService.validarParDeChaves(
                            chavePrivada,
                            certificado
                    );

            if (corresponde) {
                System.out.println(
                        "SUCESSO: A chave privada corresponde ao certificado!"
                );
            } else {
                System.out.println(
                        "ERRO: A chave privada nao corresponde ao certificado."
                );
            }

        } catch (Exception e) {
            System.err.println("Falha no teste da chave privada:");
            System.err.println(e.getMessage());
        }
    }
}
