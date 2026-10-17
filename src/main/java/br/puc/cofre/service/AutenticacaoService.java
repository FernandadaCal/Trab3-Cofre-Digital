/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.service;

import br.puc.cofre.database.UsuarioRepository;
import br.puc.cofre.model.Usuario;
import br.puc.cofre.security.SenhaService;
import br.puc.cofre.security.TOTP;
import br.puc.cofre.security.TokenService;
import java.sql.SQLException;
import java.util.List;

/**
 * Regras das tres etapas de autenticacao: identificacao por login name,
 * senha pessoal pelo teclado virtual e token TOTP. Tres erros seguidos na
 * etapa 2 ou na etapa 3 bloqueiam o usuario por dois minutos.
 */
public class AutenticacaoService {

    private static final long BLOQUEIO_MS = 120_000L;
    private static final int MAXIMO_ERROS = 3;

    private final UsuarioRepository repositorio = new UsuarioRepository();
    private final SenhaService senhas = new SenhaService();
    private final TokenService tokens = new TokenService();

    public Usuario buscarUsuario(String email) throws SQLException {
        return repositorio.buscarPorEmail(email);
    }

    // Etapa 1: identifica o login name. Devolve o usuario somente se ele existe
    // e nao esta bloqueado; caso contrario lanca uma excecao com o aviso ao usuario.
    public Usuario identificar(String email) throws Exception {
        Usuario usuario = repositorio.buscarPorEmail(email);

        if (usuario == null) {
            Auditoria.registrar(2005);
            throw new SecurityException("Login name nao identificado.");
        }

        if (estaBloqueado(usuario)) {
            Auditoria.registrar(2004, usuario);
            throw new SecurityException("Acesso bloqueado. Tente novamente em "
                    + segundosRestantesBloqueio(usuario) + " segundos.");
        }

        Auditoria.registrar(2003, usuario);
        return usuario;
    }

    public boolean estaBloqueado(Usuario usuario) throws SQLException {
        Long ate = usuario.getBloqueadoAte();
        if (ate == null) {
            return false;
        }
        if (System.currentTimeMillis() < ate) {
            return true;
        }
        // O bloqueio expirou: limpa o estado e deixa o usuario tentar de novo.
        usuario.setBloqueadoAte(null);
        usuario.setTentativasSenha(0);
        usuario.setTentativasToken(0);
        repositorio.atualizarEstadoAutenticacao(usuario);
        return false;
    }

    public long segundosRestantesBloqueio(Usuario usuario) {
        Long ate = usuario.getBloqueadoAte();
        if (ate == null) {
            return 0;
        }
        return Math.max(0, (ate - System.currentTimeMillis() + 999) / 1000);
    }

    // Etapa 2: cada clique no teclado virtual vale dois algarismos possiveis.
    // Testa todas as combinacoes contra o hash BCrypt e devolve a senha
    // encontrada (necessaria para abrir o segredo TOTP) ou null se errou.
    public String validarSenhaTeclado(Usuario usuario, List<String> pares) throws SQLException {
        if (estaBloqueado(usuario)) {
            return null;
        }

        String senha = encontrarSenha(pares, usuario.getSenhaHash());

        if (senha != null) {
            usuario.setTentativasSenha(0);
            repositorio.atualizarEstadoAutenticacao(usuario);
            Auditoria.registrar(3003, usuario);
            return senha;
        }

        int erros = usuario.getTentativasSenha() + 1;
        usuario.setTentativasSenha(erros);
        // 3004, 3005 e 3006 sao o primeiro, segundo e terceiro erro.
        Auditoria.registrar(3003 + Math.min(erros, MAXIMO_ERROS), usuario);

        if (erros >= MAXIMO_ERROS) {
            bloquear(usuario);
            Auditoria.registrar(3007, usuario);
        }
        repositorio.atualizarEstadoAutenticacao(usuario);
        return null;
    }

    // Monta todas as sequencias possiveis a partir dos pares escolhidos
    // ("3 ou 7", ...) e confere cada uma com BCrypt.
    String encontrarSenha(List<String> pares, String hash) {
        if (pares == null || pares.size() < 8 || pares.size() > 10) {
            return null;
        }
        String[][] opcoes = new String[pares.size()][];
        for (int i = 0; i < pares.size(); i++) {
            String[] p = pares.get(i).split(" ou ");
            if (p.length != 2 || !p[0].matches("[0-9]") || !p[1].matches("[0-9]")) {
                return null;
            }
            opcoes[i] = p;
        }
        int total = 1 << pares.size();
        for (int mascara = 0; mascara < total; mascara++) {
            StringBuilder candidato = new StringBuilder();
            for (int i = 0; i < opcoes.length; i++) {
                candidato.append(opcoes[i][(mascara >> i) & 1]);
            }
            if (senhas.verificarSenha(candidato.toString(), hash)) {
                return candidato.toString();
            }
        }
        return null;
    }

    // Etapa 3: o segredo TOTP esta cifrado com a senha pessoal, por isso a
    // senha verificada na etapa 2 e necessaria aqui.
    public boolean validarToken(Usuario usuario, String senhaPessoal, String codigo)
            throws Exception {
        if (estaBloqueado(usuario)) {
            return false;
        }

        String segredo = tokens.descriptografarSegredo(usuario.getTokenKey(), senhaPessoal);
        boolean correto = new TOTP(segredo, 30).validateCode(codigo);

        if (correto) {
            usuario.setTentativasToken(0);
            usuario.setTentativasSenha(0);
            usuario.setTotalAcessos(usuario.getTotalAcessos() + 1);
            repositorio.atualizarEstadoAutenticacao(usuario);
            Auditoria.registrar(4003, usuario);
            return true;
        }

        int erros = usuario.getTentativasToken() + 1;
        usuario.setTentativasToken(erros);
        // 4004, 4005 e 4006 sao o primeiro, segundo e terceiro erro.
        Auditoria.registrar(4003 + Math.min(erros, MAXIMO_ERROS), usuario);

        if (erros >= MAXIMO_ERROS) {
            bloquear(usuario);
            Auditoria.registrar(4007, usuario);
        }
        repositorio.atualizarEstadoAutenticacao(usuario);
        return false;
    }

    // Soma uma consulta a pasta segura ao contador do usuario.
    public void contabilizarConsulta(Usuario usuario) throws SQLException {
        usuario.setTotalConsultas(usuario.getTotalConsultas() + 1);
        repositorio.atualizarEstadoAutenticacao(usuario);
    }

    private void bloquear(Usuario usuario) {
        usuario.setBloqueadoAte(System.currentTimeMillis() + BLOQUEIO_MS);
        usuario.setTentativasSenha(0);
        usuario.setTentativasToken(0);
    }
}
