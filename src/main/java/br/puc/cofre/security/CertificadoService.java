/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/** Leitura de certificados X.509 e extracao do e-mail (login) e do nome (CN). */
public class CertificadoService {

    // OID do atributo emailAddress no campo Sujeito do certificado.
    private static final String OID_EMAIL = "1.2.840.113549.1.9.1";

    public X509Certificate carregarCertificado(String caminho)
            throws IOException, CertificateException {

        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");

        try (FileInputStream arquivo = new FileInputStream(caminho)) {

            return (X509Certificate) factory.generateCertificate(arquivo);
        }
    }

    // Reconstroi o certificado a partir do texto PEM guardado no Chaveiro.
    public X509Certificate carregarDePem(String pem) throws CertificateException {

        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");

        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    public PublicKey obterChavePublica(X509Certificate certificado) {

        return certificado.getPublicKey();
    }

    public void validarValidade(X509Certificate certificado)
            throws CertificateException {

        certificado.checkValidity();
    }

    // E-mail do Sujeito: e o login name do usuario no sistema.
    public String extrairEmail(X509Certificate certificado) throws Exception {
        return atributoDoSujeito(certificado, "EMAILADDRESS");
    }

    // CN (Friendly Name) do Sujeito: e o nome do usuario no sistema.
    public String extrairNome(X509Certificate certificado) throws Exception {
        return atributoDoSujeito(certificado, "CN");
    }

    // Texto com os campos exigidos na tela de confirmacao do cadastro.
    public String descreverParaConfirmacao(X509Certificate certificado) throws Exception {

        StringBuilder texto = new StringBuilder();
        texto.append("Versao: ").append(certificado.getVersion()).append('\n');
        texto.append("Serie: ").append(certificado.getSerialNumber()).append('\n');
        texto.append("Validade: de ").append(certificado.getNotBefore())
             .append(" ate ").append(certificado.getNotAfter()).append('\n');
        texto.append("Tipo de assinatura: ").append(certificado.getSigAlgName()).append('\n');
        texto.append("Emissor: ").append(certificado.getIssuerX500Principal()).append('\n');
        texto.append("Sujeito (Friendly Name): ").append(extrairNome(certificado)).append('\n');
        texto.append("E-mail: ").append(extrairEmail(certificado));
        return texto.toString();
    }

    // Exibe os principais dados do certificado (usado no TesteCertificado).
    public void exibirInformacoes(X509Certificate certificado) {

        System.out.println("Versao: " + certificado.getVersion());
        System.out.println("Serie: " + certificado.getSerialNumber());
        System.out.println("Valido de: " + certificado.getNotBefore());
        System.out.println("Valido ate: " + certificado.getNotAfter());
        System.out.println("Algoritmo: " + certificado.getSigAlgName());
        System.out.println("Emissor: " + certificado.getIssuerX500Principal());
        System.out.println("Sujeito: " + certificado.getSubjectX500Principal());
        System.out.println("Chave publica: "
                + certificado.getPublicKey().getAlgorithm());
    }

    // Percorre o DN do Sujeito procurando o atributo pedido.
    // O e-mail pode vir como String ou como valor ASN.1 (IA5String) em bytes.
    private String atributoDoSujeito(X509Certificate certificado, String nome)
            throws Exception {

        LdapName dn = new LdapName(certificado.getSubjectX500Principal().getName());

        for (Rdn rdn : dn.getRdns()) {
            boolean ehOAtributo = rdn.getType().equalsIgnoreCase(nome)
                    || (nome.equals("EMAILADDRESS") && rdn.getType().equals(OID_EMAIL));

            if (!ehOAtributo) {
                continue;
            }

            Object valor = rdn.getValue();

            if (valor instanceof String texto) {
                return texto;
            }

            if (valor instanceof byte[] bytes
                    && bytes.length > 2
                    && bytes[0] == 0x16
                    && (bytes[1] & 0xff) == bytes.length - 2) {
                return new String(bytes, 2, bytes.length - 2, StandardCharsets.US_ASCII);
            }
        }

        return null;
    }
}
