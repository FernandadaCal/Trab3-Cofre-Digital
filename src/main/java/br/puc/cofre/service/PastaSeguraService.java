/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.service;

import br.puc.cofre.database.ChaveiroRepository;
import br.puc.cofre.model.ArquivoProtegido;
import br.puc.cofre.model.Compartilhamento;
import br.puc.cofre.model.Usuario;
import br.puc.cofre.security.ArquivoProtegidoService;
import br.puc.cofre.security.CertificadoService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Consulta a pasta segura: le os indices (index e share), aplica a politica
 * de controle de acesso e recupera os arquivos protegidos.
 * Todos os eventos sao registrados com os codigos 7005 a 7021.
 */
public class PastaSeguraService {

    /** Conteudo dos dois indices da pasta, ja decriptados e verificados. */
    public record Indices(List<ArquivoProtegido> index, List<Compartilhamento> share) {}

    private final ArquivoProtegidoService arquivos = new ArquivoProtegidoService();
    private final ChaveiroRepository chaveiro = new ChaveiroRepository();
    private final CertificadoService certificados = new CertificadoService();

    // Le index e share. Os dois pertencem ao administrador do sistema, por isso
    // o envelope e aberto com a chave privada do administrador (mantida em
    // memoria desde a partida) e a assinatura e conferida com a chave publica dele.
    public Indices carregarIndices(Path pasta, PrivateKey chaveAdmin,
                                   PublicKey publicaAdmin, Usuario usuario) throws Exception {

        byte[] textoIndex = lerIndice(pasta, "index", chaveAdmin, publicaAdmin, usuario,
                                      7005, 7006, 7007, 7008);
        List<ArquivoProtegido> index = interpretarIndex(textoIndex);

        byte[] textoShare = lerIndice(pasta, "share", chaveAdmin, publicaAdmin, usuario,
                                      7010, 7011, 7012, 7013);
        List<Compartilhamento> share = interpretarShare(textoShare);

        return new Indices(index, share);
    }

    // Decripta e verifica um dos indices, registrando sucesso ou falha.
    private byte[] lerIndice(Path pasta, String nome, PrivateKey chaveAdmin,
                             PublicKey publicaAdmin, Usuario usuario,
                             int midDecriptado, int midVerificado,
                             int midFalhaDecriptacao, int midFalhaVerificacao) throws Exception {

        byte[] textoPlano;
        try {
            byte[] semente = arquivos.abrirEnvelope(pasta.resolve(nome + ".env"), chaveAdmin);
            textoPlano = arquivos.decriptar(pasta.resolve(nome + ".enc"), semente);
        } catch (Exception e) {
            Auditoria.registrar(midFalhaDecriptacao, usuario);
            throw new SecurityException("Falha na decriptacao do arquivo " + nome
                    + " (sigilo): " + e.getMessage());
        }
        Auditoria.registrar(midDecriptado, usuario);

        boolean autentico;
        try {
            autentico = arquivos.verificarAssinatura(textoPlano,
                    pasta.resolve(nome + ".asd"), publicaAdmin);
        } catch (Exception e) {
            autentico = false;
        }
        if (!autentico) {
            Auditoria.registrar(midFalhaVerificacao, usuario);
            throw new SecurityException("Falha na verificacao de integridade e autenticidade do arquivo "
                    + nome + ".");
        }
        Auditoria.registrar(midVerificado, usuario);

        return textoPlano;
    }

    // Linhas: NOME_CODIGO NOME_SECRETO DONO GRUPO
    public List<ArquivoProtegido> interpretarIndex(byte[] texto) {
        List<ArquivoProtegido> lista = new ArrayList<>();
        for (String linha : new String(texto, StandardCharsets.UTF_8).split("\n")) {
            if (linha.isBlank()) {
                continue;
            }
            String[] campos = linha.trim().split("\\s+");
            if (campos.length != 4) {
                throw new IllegalArgumentException("Linha invalida no arquivo index: " + linha);
            }
            lista.add(new ArquivoProtegido(campos[0], campos[1], campos[2], campos[3]));
        }
        return lista;
    }

    // Linhas: NOME_CODIGO ID_COMPARTILHAMENTO USUARIO_AUTORIZADO
    public List<Compartilhamento> interpretarShare(byte[] texto) {
        List<Compartilhamento> lista = new ArrayList<>();
        for (String linha : new String(texto, StandardCharsets.UTF_8).split("\n")) {
            if (linha.isBlank()) {
                continue;
            }
            String[] campos = linha.trim().split("\\s+");
            if (campos.length != 3 || !campos[1].matches("[0-9]+")) {
                throw new IllegalArgumentException("Linha invalida no arquivo share: " + linha);
            }
            lista.add(new Compartilhamento(campos[0], Integer.parseInt(campos[1]), campos[2]));
        }
        return lista;
    }

    // Politica de acesso: dono do arquivo, mesmo grupo do arquivo ou
    // compartilhamento explicito para o usuario.
    public boolean temPermissao(Usuario usuario, ArquivoProtegido arquivo,
                                List<Compartilhamento> share) {
        return ehDono(usuario, arquivo)
                || ehDoGrupo(usuario, arquivo)
                || compartilhamentoPara(usuario, arquivo, share) != null;
    }

    public List<ArquivoProtegido> arquivosAutorizados(Usuario usuario, Indices indices) {
        List<ArquivoProtegido> autorizados = new ArrayList<>();
        for (ArquivoProtegido arquivo : indices.index()) {
            if (temPermissao(usuario, arquivo, indices.share())) {
                autorizados.add(arquivo);
            }
        }
        return autorizados;
    }

    // Texto curto explicando por que o usuario enxerga o arquivo na listagem.
    public String origemAcesso(Usuario usuario, ArquivoProtegido arquivo,
                               List<Compartilhamento> share) {
        if (ehDono(usuario, arquivo)) {
            return "dono";
        }
        if (compartilhamentoPara(usuario, arquivo, share) != null) {
            return "compartilhado";
        }
        if (ehDoGrupo(usuario, arquivo)) {
            return "grupo";
        }
        return "sem acesso";
    }

    // Recupera o arquivo selecionado: abre o envelope correto, decripta,
    // verifica a assinatura do dono e so entao grava o arquivo com o nome secreto.
    // Devolve o caminho do arquivo gravado.
    public Path recuperarArquivo(Path pasta, ArquivoProtegido arquivo, Usuario usuario,
                                 PrivateKey chaveUsuario, List<Compartilhamento> share)
            throws Exception {

        String nome = arquivo.nomeCodigo();
        Auditoria.registrar(7015, usuario, nome);

        // A permissao e conferida de novo na selecao, nao so na listagem.
        if (!temPermissao(usuario, arquivo, share)) {
            Auditoria.registrar(7017, usuario, nome);
            throw new SecurityException("Voce nao tem permissao de acesso ao arquivo "
                    + arquivo.nomeSecreto() + ".");
        }
        Auditoria.registrar(7016, usuario, nome);

        // Escolha do envelope: o dono abre o .env; quem recebeu compartilhamento
        // abre o .N.shr. Quem so e do grupo nao possui envelope proprio e, por isso,
        // nao consegue recuperar a semente (erro de sigilo).
        Path envelope;
        if (ehDono(usuario, arquivo)) {
            envelope = pasta.resolve(nome + ".env");
        } else {
            Compartilhamento comp = compartilhamentoPara(usuario, arquivo, share);
            if (comp == null) {
                Auditoria.registrar(7020, usuario, nome);
                throw new SecurityException("Erro de sigilo: nao existe envelope digital do arquivo "
                        + arquivo.nomeSecreto() + " para o seu usuario (acesso apenas por grupo).");
            }
            envelope = pasta.resolve(comp.nomeEnvelope());
        }

        byte[] textoPlano;
        try {
            byte[] semente = arquivos.abrirEnvelope(envelope, chaveUsuario);
            textoPlano = arquivos.decriptar(pasta.resolve(nome + ".enc"), semente);
        } catch (Exception e) {
            Auditoria.registrar(7020, usuario, nome);
            throw new SecurityException("Falha na decriptacao do arquivo " + arquivo.nomeSecreto()
                    + " (sigilo): " + e.getMessage());
        }
        Auditoria.registrar(7018, usuario, nome);

        // A assinatura foi feita pelo dono; a chave publica dele vem do Chaveiro.
        boolean autentico;
        try {
            PublicKey publicaDono = chavePublicaDoUsuario(arquivo.dono());
            autentico = publicaDono != null && arquivos.verificarAssinatura(textoPlano,
                    pasta.resolve(nome + ".asd"), publicaDono);
        } catch (Exception e) {
            autentico = false;
        }
        if (!autentico) {
            Auditoria.registrar(7021, usuario, nome);
            throw new SecurityException("Falha na verificacao de integridade e autenticidade do arquivo "
                    + arquivo.nomeSecreto() + ". Nenhum arquivo foi gravado.");
        }
        Auditoria.registrar(7019, usuario, nome);

        // Somente depois de todas as verificacoes o conteudo vai para o disco.
        Path destino = pasta.resolve(arquivo.nomeSecreto());
        Files.write(destino, textoPlano);
        return destino;
    }

    // Chave publica de um usuario cadastrado, a partir do certificado no Chaveiro.
    private PublicKey chavePublicaDoUsuario(String email) throws Exception {
        String pem = chaveiro.buscarCertificadoPorEmail(email);
        if (pem == null) {
            return null;
        }
        return certificados.obterChavePublica(certificados.carregarDePem(pem));
    }

    private boolean ehDono(Usuario usuario, ArquivoProtegido arquivo) {
        return arquivo.dono().equalsIgnoreCase(usuario.getEmail());
    }

    // O indice usa os nomes de grupo em minusculas ("administrador", "usuario").
    private boolean ehDoGrupo(Usuario usuario, ArquivoProtegido arquivo) {
        return arquivo.grupo().equalsIgnoreCase(Usuario.nomeDoGrupo(usuario.getGid()));
    }

    private Compartilhamento compartilhamentoPara(Usuario usuario, ArquivoProtegido arquivo,
                                                  List<Compartilhamento> share) {
        for (Compartilhamento comp : share) {
            if (comp.nomeCodigo().equals(arquivo.nomeCodigo())
                    && comp.usuarioAutorizado().equalsIgnoreCase(usuario.getEmail())) {
                return comp;
            }
        }
        return null;
    }
}
