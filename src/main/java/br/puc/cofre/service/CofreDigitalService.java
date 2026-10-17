/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.service;

import br.puc.cofre.database.ChaveiroRepository;
import br.puc.cofre.database.UsuarioRepository;
import br.puc.cofre.model.ArquivoProtegido;
import br.puc.cofre.model.Usuario;
import br.puc.cofre.security.CertificadoService;
import br.puc.cofre.security.ChaveService;
import br.puc.cofre.service.CadastroService.DadosValidados;
import br.puc.cofre.service.CadastroService.ResultadoCadastro;
import br.puc.cofre.service.PastaSeguraService.Indices;
import br.puc.cofre.view.Componentes;
import br.puc.cofre.view.TecladoVirtual;
import br.puc.cofre.view.TelaAutenticacao;
import br.puc.cofre.view.TelaCadastro;
import br.puc.cofre.view.TelaConsulta;
import br.puc.cofre.view.TelaInicializacao;
import br.puc.cofre.view.TelaPrincipal;
import br.puc.cofre.view.TelaSaida;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.swing.JDialog;

/**
 * Fluxo completo do Cofre Digital: partida do sistema, autenticacao em tres
 * etapas e as telas Principal, Cadastro, Consulta e Saida. As janelas ficam no
 * pacote view; aqui ficam as regras, a ordem das etapas e os registros de auditoria.
 *
 * Este fluxo roda na thread principal. Cada tela e uma janela modal que so
 * devolve o controle quando o usuario pressiona um botao.
 */
public class CofreDigitalService {

    private final UsuarioRepository usuarios = new UsuarioRepository();
    private final ChaveiroRepository chaveiro = new ChaveiroRepository();
    private final CadastroService cadastro = new CadastroService();
    private final AutenticacaoService autenticacao = new AutenticacaoService();
    private final CertificadoService certificados = new CertificadoService();
    private final ChaveService chaves = new ChaveService();
    private final PastaSeguraService pastaSegura = new PastaSeguraService();

    // Material do administrador do sistema mantido em memoria durante a execucao.
    // E necessario para abrir os envelopes dos arquivos index e share.
    private String fraseSecretaAdmin;
    private PrivateKey chavePrivadaAdmin;
    private PublicKey chavePublicaAdmin;

    // Dados do administrador cadastrado na primeira execucao (preenchido pela Tela de Cadastro).
    private DadosValidados dadosDoCadastroInicial;

    public void executar() throws Exception {
        Auditoria.registrar(1001);
        try {
            if (!usuarios.existeAdministrador()) {
                Auditoria.registrar(1005);
                cadastrarAdministradorInicial();
            } else {
                Auditoria.registrar(1006);
                validarAdministradorNaInicializacao();
            }
            loopDeSessoes();
        } finally {
            descartarMaterialDoAdministrador();
            Auditoria.registrar(1002);
        }
    }

    // ------------------------------------------------------------------
    // Partida do sistema
    // ------------------------------------------------------------------

    private void cadastrarAdministradorInicial() throws Exception {
        Componentes.mostrarInfo("Cofre Digital - Primeira execucao",
                "Nenhum usuario cadastrado.\nCadastre o administrador da pasta segura.");

        DadosValidados dados = telaCadastro(null, true);
        if (dados == null) {
            throw new IllegalStateException("Cadastro inicial do administrador nao concluido.");
        }

        // A frase secreta digitada no cadastro fica em memoria ate o encerramento.
        guardarMaterialDoAdministrador(dados.chavePrivada(), dados.certificado(), null);
    }

    // Da segunda execucao em diante: a frase secreta do administrador e validada
    // da mesma forma que no cadastro (decriptar a chave guardada no Chaveiro e
    // conferir a assinatura de 10240 bytes com o certificado). Falhou, encerra.
    private void validarAdministradorNaInicializacao() throws Exception {
        Usuario admin = usuarios.buscarAdministradorDoSistema();

        String frase = TelaInicializacao.pedirFraseAdministrador(admin.getEmail());
        if (frase == null) {
            throw new SecurityException("Frase secreta do administrador nao informada. "
                    + "O sistema sera encerrado.");
        }

        X509Certificate certificado = certificados.carregarDePem(
                chaveiro.buscarCertificado(admin.getUid()));
        byte[] chaveCifrada = chaveiro.buscarChavePrivada(admin.getUid());

        PrivateKey chavePrivada;
        try {
            chavePrivada = chaves.carregarChavePrivada(chaveCifrada, frase);
        } catch (Exception e) {
            throw new SecurityException("Frase secreta do administrador invalida. "
                    + "O sistema sera encerrado.");
        }
        if (!chaves.validarParDeChaves(chavePrivada, certificado)) {
            throw new SecurityException("A chave privada do administrador nao corresponde ao "
                    + "certificado armazenado. O sistema sera encerrado.");
        }

        guardarMaterialDoAdministrador(chavePrivada, certificado, frase);
        Componentes.mostrarInfo("Cofre Digital", "Administrador validado.");
    }

    private void guardarMaterialDoAdministrador(PrivateKey chavePrivada,
                                                X509Certificate certificado, String frase) {
        this.chavePrivadaAdmin = chavePrivada;
        this.chavePublicaAdmin = certificado.getPublicKey();
        this.fraseSecretaAdmin = frase;
    }

    // Ao encerrar, o material sensivel do administrador e descartado.
    private void descartarMaterialDoAdministrador() {
        this.fraseSecretaAdmin = null;
        this.chavePrivadaAdmin = null;
        this.chavePublicaAdmin = null;
    }

    // ------------------------------------------------------------------
    // Sessoes e autenticacao
    // ------------------------------------------------------------------

    private void loopDeSessoes() throws Exception {
        while (true) {
            Usuario usuario = autenticar();
            if (usuario == null) {
                return;
            }
            Auditoria.registrar(1003, usuario);
            boolean encerrarSistema = telaPrincipal(usuario);
            Auditoria.registrar(1004, usuario);
            if (encerrarSistema) {
                return;
            }
        }
    }

    // Executa as tres etapas. Devolve o usuario autenticado, ou null se o
    // operador pediu para encerrar o sistema na tela de login.
    private Usuario autenticar() throws Exception {
        while (true) {
            // Etapa 1: identificacao pelo login name (e-mail do certificado).
            Auditoria.registrar(2001);
            String login = TelaAutenticacao.pedirLogin();
            if (login == null) {
                Auditoria.registrar(2002);
                return null;
            }

            Usuario usuario;
            try {
                usuario = autenticacao.identificar(login);
            } catch (Exception e) {
                Componentes.mostrarErro("Autenticacao - Etapa 1", e.getMessage());
                Auditoria.registrar(2002);
                continue;
            }
            Auditoria.registrar(2002);

            // Etapa 2: senha pessoal pelo teclado virtual.
            String senha = etapaSenha(usuario);
            if (senha == null) {
                continue;
            }

            // Etapa 3: token TOTP.
            if (!etapaToken(usuario, senha)) {
                continue;
            }

            return usuario;
        }
    }

    // Repete a etapa 2 enquanto houver tentativas. Devolve a senha em claro
    // (necessaria para abrir o segredo TOTP) ou null para voltar a etapa 1.
    private String etapaSenha(Usuario usuario) throws Exception {
        Auditoria.registrar(3001, usuario);
        try {
            while (true) {
                List<String> pares = TecladoVirtual.solicitarPares();
                if (pares.isEmpty()) {
                    Componentes.mostrarErro("Autenticacao - Etapa 2",
                            "Teclado virtual fechado. Voltando a etapa 1.");
                    return null;
                }

                // A conferencia testa todas as combinacoes dos pares com BCrypt
                // e pode levar alguns segundos; o aviso evita a impressao de travamento.
                JDialog aguarde = Componentes.aguarde("Verificando a senha pessoal...");
                String senha;
                try {
                    senha = autenticacao.validarSenhaTeclado(usuario, pares);
                } finally {
                    aguarde.dispose();
                }
                if (senha != null) {
                    return senha;
                }

                if (usuario.getBloqueadoAte() != null) {
                    Componentes.mostrarErro("Autenticacao - Etapa 2",
                            "Terceiro erro consecutivo de senha: acesso bloqueado por 2 minutos.\n"
                            + "Voltando a etapa 1.");
                    return null;
                }
                Componentes.mostrarErro("Autenticacao - Etapa 2", "Senha pessoal incorreta (erro "
                        + usuario.getTentativasSenha() + " de 3). Tente novamente.");
            }
        } finally {
            Auditoria.registrar(3002, usuario);
        }
    }

    // Repete a etapa 3 enquanto houver tentativas. Devolve false para voltar a etapa 1.
    private boolean etapaToken(Usuario usuario, String senha) throws Exception {
        Auditoria.registrar(4001, usuario);
        try {
            while (true) {
                String codigo = TelaAutenticacao.pedirToken(usuario);
                if (codigo == null) {
                    return false;
                }

                if (autenticacao.validarToken(usuario, senha, codigo)) {
                    return true;
                }

                if (usuario.getBloqueadoAte() != null) {
                    Componentes.mostrarErro("Autenticacao - Etapa 3",
                            "Terceiro erro consecutivo de token: acesso bloqueado por 2 minutos.\n"
                            + "Voltando a etapa 1.");
                    return false;
                }
                Componentes.mostrarErro("Autenticacao - Etapa 3", "Token incorreto (erro "
                        + usuario.getTentativasToken() + " de 3). Tente novamente.");
            }
        } finally {
            Auditoria.registrar(4002, usuario);
        }
    }

    // ------------------------------------------------------------------
    // Tela Principal
    // ------------------------------------------------------------------

    // Devolve true quando o usuario escolheu "Encerrar Sistema".
    private boolean telaPrincipal(Usuario usuario) throws Exception {
        while (true) {
            Auditoria.registrar(5001, usuario);
            int opcao = TelaPrincipal.mostrar(usuario);

            if (opcao == TelaPrincipal.CADASTRAR && usuario.getGid() == 1) {
                Auditoria.registrar(5002, usuario);
                telaCadastro(usuario, false);
            } else if (opcao == TelaPrincipal.CONSULTAR) {
                Auditoria.registrar(5003, usuario);
                telaConsulta(usuario);
            } else {
                Auditoria.registrar(5004, usuario);
                int saida = telaSaida(usuario);
                if (saida == TelaSaida.ENCERRAR_SESSAO) {
                    return false;
                }
                if (saida == TelaSaida.ENCERRAR_SISTEMA) {
                    return true;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Tela de Cadastro
    // ------------------------------------------------------------------

    // operador: quem esta cadastrando (null no cadastro inicial).
    // cadastroInicial: true na primeira partida; o grupo e fixo em Administrador
    // e a tela termina assim que o cadastro e efetivado, devolvendo os dados
    // validados. Nos demais casos devolve null.
    private DadosValidados telaCadastro(Usuario operador, boolean cadastroInicial) throws Exception {
        Auditoria.registrar(6001, operador);
        dadosDoCadastroInicial = null;

        TelaCadastro.mostrar(operador, cadastroInicial, new TelaCadastro.Acoes() {
            @Override
            public int totalUsuarios() throws Exception {
                return usuarios.contarUsuarios();
            }

            @Override
            public boolean cadastrar(String caminhoCertificado, String caminhoChave, String frase,
                                     int gid, String senha, String confirmacao) throws Exception {
                return efetuarCadastro(operador, cadastroInicial, caminhoCertificado, caminhoChave,
                                       frase, gid, senha, confirmacao);
            }

            @Override
            public void voltar() {
                Auditoria.registrar(6010, operador);
            }
        });

        return cadastroInicial ? dadosDoCadastroInicial : null;
    }

    // Botao Cadastrar: valida, mostra o certificado para confirmacao e grava.
    // Devolve true quando o usuario foi cadastrado.
    private boolean efetuarCadastro(Usuario operador, boolean cadastroInicial,
                                    String caminhoCertificado, String caminhoChave, String frase,
                                    int gid, String senha, String confirmacao) throws Exception {
        Auditoria.registrar(6002, operador);

        DadosValidados dados;
        try {
            dados = cadastro.validar(caminhoCertificado, caminhoChave, frase, gid,
                                     senha, confirmacao, operador);
        } catch (Exception e) {
            Componentes.mostrarErro("Cadastro nao realizado", e.getMessage());
            return false;
        }

        boolean confirmado = TelaCadastro.confirmarCertificado(
                certificados.descreverParaConfirmacao(dados.certificado()), Usuario.nomeDoGrupo(gid));
        if (!confirmado) {
            Auditoria.registrar(6009, operador);
            Componentes.mostrarErro("Cadastro nao realizado", "Dados rejeitados. Cadastro nao realizado.");
            return false;
        }
        Auditoria.registrar(6008, operador);

        ResultadoCadastro resultado;
        try {
            resultado = cadastro.confirmar(dados);
        } catch (Exception e) {
            Componentes.mostrarErro("Cadastro nao realizado", e.getMessage());
            return false;
        }

        TelaCadastro.mostrarSegredo(resultado.nome(), resultado.email(), resultado.uid(),
                                    resultado.segredoBase32());
        if (cadastroInicial) {
            dadosDoCadastroInicial = dados;
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Tela de Consulta da pasta de arquivos secretos
    // ------------------------------------------------------------------

    private void telaConsulta(Usuario usuario) {
        Auditoria.registrar(7001, usuario);

        TelaConsulta.mostrar(usuario, new TelaConsulta.Acoes() {
            // Estado da ultima listagem bem-sucedida, usado na recuperacao.
            private Path pasta;
            private PrivateKey chaveUsuario;
            private Indices indices;

            @Override
            public List<ArquivoProtegido> listar(String caminhoPasta, String frase) throws Exception {
                Auditoria.registrar(7003, usuario);

                Path candidata = null;
                try {
                    candidata = caminhoPasta.isBlank() ? null : Path.of(caminhoPasta);
                } catch (InvalidPathException e) {
                    candidata = null;
                }
                if (candidata == null || !Files.isDirectory(candidata)) {
                    Auditoria.registrar(7004, usuario);
                    throw new IllegalArgumentException("Caminho de pasta invalido.");
                }

                PrivateKey chave = validarFraseSecreta(usuario, frase);
                Indices lidos = pastaSegura.carregarIndices(candidata, chavePrivadaAdmin,
                                                            chavePublicaAdmin, usuario);

                autenticacao.contabilizarConsulta(usuario);
                List<ArquivoProtegido> lista = pastaSegura.arquivosAutorizados(usuario, lidos);
                Auditoria.registrar(7009, usuario);
                Auditoria.registrar(7014, usuario);

                pasta = candidata;
                chaveUsuario = chave;
                indices = lidos;
                return lista;
            }

            @Override
            public String origemAcesso(ArquivoProtegido arquivo) {
                return pastaSegura.origemAcesso(usuario, arquivo, indices.share());
            }

            @Override
            public String recuperar(ArquivoProtegido arquivo) throws Exception {
                Path gravado = pastaSegura.recuperarArquivo(pasta, arquivo, usuario,
                                                            chaveUsuario, indices.share());
                return "Arquivo " + arquivo.nomeSecreto()
                        + " decriptado e verificado com sucesso.\nGravado em: " + gravado;
            }

            @Override
            public int totalConsultas() {
                return usuario.getTotalConsultas();
            }

            @Override
            public void voltar() {
                Auditoria.registrar(7002, usuario);
            }
        });
    }

    // Valida a frase secreta do usuario corrente do mesmo modo que no cadastro:
    // decripta a chave privada guardada no Chaveiro e confere a assinatura de
    // 10240 bytes com o certificado dele. Devolve a chave privada recuperada.
    private PrivateKey validarFraseSecreta(Usuario usuario, String frase) throws Exception {
        X509Certificate certificado = certificados.carregarDePem(
                chaveiro.buscarCertificado(usuario.getUid()));
        byte[] chaveCifrada = chaveiro.buscarChavePrivada(usuario.getUid());

        PrivateKey chavePrivada;
        try {
            chavePrivada = chaves.carregarChavePrivada(chaveCifrada, frase);
        } catch (Exception e) {
            Auditoria.registrar(6006, usuario);
            throw new SecurityException("Frase secreta invalida: nao foi possivel decriptar a sua chave privada.");
        }
        if (!chaves.validarParDeChaves(chavePrivada, certificado)) {
            Auditoria.registrar(6007, usuario);
            throw new SecurityException("Assinatura digital invalida: a chave privada nao corresponde ao seu certificado.");
        }
        return chavePrivada;
    }

    // ------------------------------------------------------------------
    // Tela de Saida
    // ------------------------------------------------------------------

    // Devolve a opcao da TelaSaida (encerrar sessao, encerrar sistema ou voltar ao menu).
    private int telaSaida(Usuario usuario) {
        Auditoria.registrar(8001, usuario);
        int opcao = TelaSaida.mostrar(usuario);
        if (opcao == TelaSaida.ENCERRAR_SESSAO) {
            Auditoria.registrar(8002, usuario);
        } else if (opcao == TelaSaida.ENCERRAR_SISTEMA) {
            Auditoria.registrar(8003, usuario);
        } else {
            Auditoria.registrar(8004, usuario);
        }
        return opcao;
    }
}
