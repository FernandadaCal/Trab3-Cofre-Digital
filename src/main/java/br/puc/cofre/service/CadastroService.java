/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.service;

import br.puc.cofre.database.ChaveiroRepository;
import br.puc.cofre.database.DatabaseConnection;
import br.puc.cofre.database.UsuarioRepository;
import br.puc.cofre.model.Usuario;
import br.puc.cofre.security.CertificadoService;
import br.puc.cofre.security.ChaveService;
import br.puc.cofre.security.SenhaService;
import br.puc.cofre.security.TokenService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.Connection;

/**
 * Cadastro em duas fases: primeiro valida tudo (senha, certificado, chave
 * privada e frase secreta) e devolve os dados para a tela de confirmacao;
 * depois, se o operador confirmar, grava o usuario em uma unica transacao.
 */
public class CadastroService {

    /** Dados ja validados, prontos para confirmacao e gravacao. */
    public record DadosValidados(X509Certificate certificado, String email, String nome,
                                 String certificadoPem, byte[] chaveCifrada,
                                 PrivateKey chavePrivada, int gid, String senhaPessoal) {}

    public record ResultadoCadastro(int uid, String email, String nome,
                                    String segredoBase32) {}

    private final UsuarioRepository usuarios = new UsuarioRepository();
    private final ChaveiroRepository chaveiro = new ChaveiroRepository();
    private final CertificadoService certificados = new CertificadoService();
    private final ChaveService chaves = new ChaveService();
    private final SenhaService senhas = new SenhaService();
    private final TokenService tokens = new TokenService();

    // Fase 1: critica os campos do formulario. O operador e quem esta cadastrando
    // (null no cadastro inicial do administrador) e serve para os registros 6003 a 6007.
    public DadosValidados validar(String caminhoCertificado, String caminhoChave,
                                  String fraseSecreta, int gid, String senhaPessoal,
                                  String confirmacao, Usuario operador) throws Exception {

        if (gid != 1 && gid != 2) {
            throw new IllegalArgumentException("Grupo invalido: escolha Administrador ou Usuario.");
        }

        if (!senhas.validarFormato(senhaPessoal)) {
            Auditoria.registrar(6003, operador);
            throw new IllegalArgumentException("Senha pessoal invalida: use 8 a 10 algarismos, "
                    + "sem numeros repetidos em sequencia.");
        }
        if (!senhaPessoal.equals(confirmacao)) {
            Auditoria.registrar(6003, operador);
            throw new IllegalArgumentException("A senha pessoal e a confirmacao sao diferentes.");
        }

        X509Certificate certificado;
        String email;
        String nome;
        try {
            certificado = certificados.carregarCertificado(caminhoCertificado);
            certificado.checkValidity();
            email = certificados.extrairEmail(certificado);
            nome = certificados.extrairNome(certificado);
        } catch (Exception e) {
            Auditoria.registrar(6004, operador);
            throw new IllegalArgumentException("Caminho do certificado digital invalido ou certificado "
                    + "nao aceito: " + e.getMessage());
        }
        if (email == null || email.isBlank() || nome == null || nome.isBlank()) {
            Auditoria.registrar(6004, operador);
            throw new IllegalArgumentException("O certificado nao possui e-mail ou nome (CN) no Sujeito.");
        }

        byte[] chaveCifrada;
        try {
            chaveCifrada = Files.readAllBytes(Path.of(caminhoChave));
        } catch (IOException | RuntimeException e) {
            Auditoria.registrar(6005, operador);
            throw new IllegalArgumentException("Caminho do arquivo da chave privada invalido.");
        }

        PrivateKey chavePrivada;
        try {
            chavePrivada = chaves.carregarChavePrivada(chaveCifrada, fraseSecreta);
        } catch (Exception e) {
            // Frase errada gera erro de padding no AES ou chave PKCS8 ilegivel.
            Auditoria.registrar(6006, operador);
            throw new SecurityException("Frase secreta invalida: nao foi possivel decriptar a chave privada.");
        }

        if (!chaves.validarParDeChaves(chavePrivada, certificado)) {
            Auditoria.registrar(6007, operador);
            throw new SecurityException("Assinatura digital invalida: a chave privada nao corresponde "
                    + "ao certificado fornecido.");
        }

        String certificadoPem = Files.readString(Path.of(caminhoCertificado), StandardCharsets.US_ASCII);

        return new DadosValidados(certificado, email, nome, certificadoPem, chaveCifrada,
                                  chavePrivada, gid, senhaPessoal);
    }

    // Fase 2: grava Usuarios e Chaveiro na mesma transacao. O login name (e-mail)
    // precisa ser unico; a tabela tambem tem UNIQUE como segunda barreira.
    public ResultadoCadastro confirmar(DadosValidados dados) throws Exception {

        String segredo = tokens.gerarSegredoBase32();
        String tokenCifrado = tokens.criptografarSegredo(segredo, dados.senhaPessoal());
        Usuario usuario = new Usuario(dados.email(), dados.nome(), dados.gid(),
                                      senhas.gerarHash(dados.senhaPessoal()), tokenCifrado);

        try (Connection conexao = DatabaseConnection.getConnection()) {
            conexao.setAutoCommit(false);
            try {
                if (usuarios.buscarPorEmail(dados.email()) != null) {
                    throw new IllegalStateException("Login name " + dados.email()
                            + " ja cadastrado no sistema.");
                }
                int uid = usuarios.inserir(usuario, conexao);
                int kid = chaveiro.inserir(uid, dados.chaveCifrada(), dados.certificadoPem(), conexao);
                usuarios.atualizarKid(uid, kid, conexao);
                conexao.commit();
                return new ResultadoCadastro(uid, dados.email(), dados.nome(), segredo);
            } catch (Exception e) {
                conexao.rollback();
                throw e;
            }
        }
    }

    // Forma antiga, em uma unica chamada, mantida para os testes automatizados.
    public ResultadoCadastro cadastrar(String caminhoCertificado, String caminhoChave,
                                       String fraseSecreta, int gid, String senhaPessoal,
                                       String confirmacao) throws Exception {
        return confirmar(validar(caminhoCertificado, caminhoChave, fraseSecreta,
                                 gid, senhaPessoal, confirmacao, null));
    }
}
