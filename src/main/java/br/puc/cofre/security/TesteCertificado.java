/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.security.cert.X509Certificate;

/** Teste manual: le e exibe o certificado do admin. */
public class TesteCertificado {

    public static void main(String[] args) {

        CertificadoService service = new CertificadoService();

        String caminho = "arquivos-teste/Keys/admin-x509.crt";

        try {
            X509Certificate certificado =
                    service.carregarCertificado(caminho);

            service.exibirInformacoes(certificado);
            service.validarValidade(certificado);

            System.out.println("Certificado dentro do prazo de validade!");

        } catch (Exception e) {
            System.err.println("Erro ao ler ou validar certificado:");
            System.err.println(e.getMessage());
        }
    }
}
