/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import br.puc.cofre.database.ChaveiroRepository;
import br.puc.cofre.database.DatabaseInitializer;
import br.puc.cofre.database.MensagemInitializer;
import br.puc.cofre.database.RegistroRepository;
import br.puc.cofre.database.RegistroRepository.Registro;
import br.puc.cofre.database.UsuarioRepository;
import br.puc.cofre.model.ArquivoProtegido;
import br.puc.cofre.model.Usuario;
import br.puc.cofre.security.CertificadoService;
import br.puc.cofre.security.ChaveService;
import br.puc.cofre.security.TOTP;
import br.puc.cofre.security.TokenService;
import br.puc.cofre.service.AutenticacaoService;
import br.puc.cofre.service.CadastroService;
import br.puc.cofre.service.PastaSeguraService;
import br.puc.cofre.service.PastaSeguraService.Indices;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Teste de integracao de ponta a ponta usando o pacote de teste do professor
 * (arquivos-teste/Keys e arquivos-teste/Files). Roda com "mvn test", em um
 * banco separado (target/cofre-teste.db) definido pelo surefire.
 * Os metodos sao executados em ordem alfabetica, pois cada etapa depende da anterior.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FluxoCompletoTest {

    private static final Path KEYS = Path.of("arquivos-teste", "Keys");
    private static final Path FILES = Path.of("arquivos-teste", "Files");

    private static final String ADMIN = "admin@inf1416.puc-rio.br";
    private static final String USER01 = "user01@inf1416.puc-rio.br";
    private static final String USER02 = "user02@inf1416.puc-rio.br";

    private static final String SENHA_ADMIN = "13572468";
    private static final String SENHA_USER01 = "98765432";
    private static final String SENHA_USER02 = "2468013579";

    private static Path pasta;

    private final UsuarioRepository usuarios = new UsuarioRepository();
    private final ChaveiroRepository chaveiro = new ChaveiroRepository();
    private final CadastroService cadastro = new CadastroService();
    private final AutenticacaoService autenticacao = new AutenticacaoService();
    private final ChaveService chaves = new ChaveService();
    private final CertificadoService certificados = new CertificadoService();
    private final PastaSeguraService pastaSegura = new PastaSeguraService();

    @BeforeClass
    public static void prepararAmbiente() throws Exception {
        // Nunca roda sobre o cofre.db real: exige a propriedade do surefire.
        String banco = System.getProperty("cofre.db");
        Assume.assumeTrue("Defina -Dcofre.db para rodar este teste", banco != null
                && !banco.equals("cofre.db"));
        Assume.assumeTrue("Pacote de teste do professor ausente", Files.isDirectory(KEYS)
                && Files.isDirectory(FILES));

        Files.createDirectories(Path.of(banco).toAbsolutePath().getParent());
        Files.deleteIfExists(Path.of(banco));
        DatabaseInitializer.initialize();
        MensagemInitializer.initialize();

        // Copia da pasta segura: os arquivos recuperados sao gravados nela.
        pasta = Files.createTempDirectory("cofre-pasta-segura");
        try (var lista = Files.list(FILES)) {
            for (Path p : lista.toList()) {
                Files.copy(p, pasta.resolve(p.getFileName()), StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    // ------------------------------------------------------------------
    // Cadastro
    // ------------------------------------------------------------------

    @Test
    public void t01_cadastraAdministradorEUsuarios() throws Exception {
        var admin = cadastro.cadastrar(chave("admin-x509.crt"), chave("admin-pkcs8-aes.key"),
                "admin", 1, SENHA_ADMIN, SENHA_ADMIN);
        assertEquals(ADMIN, admin.email());
        assertEquals("Administrator", admin.nome());
        assertEquals(32, admin.segredoBase32().length());

        cadastro.cadastrar(chave("user01-x509.crt"), chave("user01-pkcs8-aes.key"),
                "user01", 2, SENHA_USER01, SENHA_USER01);
        cadastro.cadastrar(chave("user02-x509.crt"), chave("user02-pkcs8-aes.key"),
                "user02", 2, SENHA_USER02, SENHA_USER02);

        assertEquals(3, usuarios.contarUsuarios());
        assertEquals(ADMIN, usuarios.buscarAdministradorDoSistema().getEmail());

        Usuario u1 = usuarios.buscarPorEmail(USER01);
        assertNotNull(u1.getKid());
        assertTrue(u1.getSenhaHash().startsWith("$2y$08$"));
        assertEquals(60, u1.getSenhaHash().length());
        assertNotNull(chaveiro.buscarChavePrivada(u1.getUid()));
        assertTrue(chaveiro.buscarCertificado(u1.getUid()).startsWith("Certificate:")
                || chaveiro.buscarCertificado(u1.getUid()).contains("BEGIN CERTIFICATE"));
    }

    @Test
    public void t02_cadastroRejeitaEntradasInvalidas() throws Exception {
        // E-mail repetido
        try {
            cadastro.cadastrar(chave("user01-x509.crt"), chave("user01-pkcs8-aes.key"),
                    "user01", 2, SENHA_USER01, SENHA_USER01);
            fail("login repetido deveria ser rejeitado");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("ja cadastrado"));
        }
        assertEquals(3, usuarios.contarUsuarios());

        // Frase secreta errada
        try {
            cadastro.cadastrar(chave("user01-x509.crt"), chave("user01-pkcs8-aes.key"),
                    "errada", 2, SENHA_USER01, SENHA_USER01);
            fail("frase secreta errada deveria ser rejeitada");
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("Frase secreta invalida"));
        }

        // Chave privada de outro usuario (assinatura nao confere com o certificado)
        try {
            cadastro.cadastrar(chave("user01-x509.crt"), chave("user02-pkcs8-aes.key"),
                    "user02", 2, SENHA_USER01, SENHA_USER01);
            fail("chave de outro usuario deveria ser rejeitada");
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("Assinatura digital invalida"));
        }

        // Senha com numeros repetidos em sequencia, tamanho errado e confirmacao diferente
        for (String[] par : new String[][]{{"11234567", "11234567"}, {"1234567", "1234567"},
                {"12345678", "12345679"}}) {
            try {
                cadastro.cadastrar(chave("user01-x509.crt"), chave("user01-pkcs8-aes.key"),
                        "user01", 2, par[0], par[1]);
                fail("senha invalida deveria ser rejeitada: " + par[0]);
            } catch (IllegalArgumentException e) {
                // esperado
            }
        }

        // Caminhos inexistentes
        try {
            cadastro.cadastrar("nao-existe.crt", chave("user01-pkcs8-aes.key"),
                    "user01", 2, SENHA_USER01, SENHA_USER01);
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("certificado"));
        }
        try {
            cadastro.cadastrar(chave("user01-x509.crt"), "nao-existe.key",
                    "user01", 2, SENHA_USER01, SENHA_USER01);
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("chave privada"));
        }
    }

    // ------------------------------------------------------------------
    // Autenticacao
    // ------------------------------------------------------------------

    @Test
    public void t03_etapa1IdentificaLogin() throws Exception {
        try {
            autenticacao.identificar("ninguem@inf1416.puc-rio.br");
            fail();
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("nao identificado"));
        }
        Usuario u = autenticacao.identificar(USER01);
        assertEquals(USER01, u.getEmail());
    }

    @Test
    public void t04_etapa2SenhaPeloTecladoVirtual() throws Exception {
        Usuario u = autenticacao.identificar(USER01);

        // Pares corretos (cada clique contem o algarismo certo e um vizinho)
        assertEquals(SENHA_USER01, autenticacao.validarSenhaTeclado(u, pares(SENHA_USER01)));
        assertEquals(0, u.getTentativasSenha());

        // Pares errados: tres erros seguidos bloqueiam por 2 minutos
        List<String> errados = pares("13579135");
        assertNull(autenticacao.validarSenhaTeclado(u, errados));
        assertEquals(1, u.getTentativasSenha());
        assertNull(autenticacao.validarSenhaTeclado(u, errados));
        assertEquals(2, u.getTentativasSenha());
        assertNull(autenticacao.validarSenhaTeclado(u, errados));
        assertNotNull("deveria estar bloqueado", u.getBloqueadoAte());
        assertTrue(autenticacao.segundosRestantesBloqueio(u) > 100);

        // Bloqueado nao passa da etapa 1; outro usuario continua entrando
        try {
            autenticacao.identificar(USER01);
            fail();
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("bloqueado"));
        }
        assertNotNull(autenticacao.identificar(USER02));

        // Bloqueio expirado: volta a aceitar
        u.setBloqueadoAte(System.currentTimeMillis() - 1);
        usuarios.atualizarEstadoAutenticacao(u);
        u = autenticacao.identificar(USER01);
        assertEquals(0, u.getTentativasSenha());

        // Um erro seguido de acerto zera o contador
        assertNull(autenticacao.validarSenhaTeclado(u, errados));
        assertEquals(SENHA_USER01, autenticacao.validarSenhaTeclado(u, pares(SENHA_USER01)));
        assertEquals(0, u.getTentativasSenha());
    }

    @Test
    public void t05_etapa3TokenTOTP() throws Exception {
        Usuario u = autenticacao.identificar(USER01);
        int acessosAntes = u.getTotalAcessos();

        String segredo = new TokenService().descriptografarSegredo(u.getTokenKey(), SENHA_USER01);
        String codigo = new TOTP(segredo, 30).generateCode();
        assertTrue(autenticacao.validarToken(u, SENHA_USER01, codigo));
        assertEquals(acessosAntes + 1, u.getTotalAcessos());

        String errado = codigo.equals("000000") ? "111111" : "000000";
        assertFalse(autenticacao.validarToken(u, SENHA_USER01, errado));
        assertEquals(1, u.getTentativasToken());
        assertFalse(autenticacao.validarToken(u, SENHA_USER01, "abc"));
        assertFalse(autenticacao.validarToken(u, SENHA_USER01, errado));
        assertNotNull("tres erros de token bloqueiam", u.getBloqueadoAte());

        u.setBloqueadoAte(System.currentTimeMillis() - 1);
        usuarios.atualizarEstadoAutenticacao(u);
        assertNotNull(autenticacao.identificar(USER01));
    }

    // ------------------------------------------------------------------
    // Pasta segura
    // ------------------------------------------------------------------

    @Test
    public void t06_listagemRespeitaPoliticaDeAcesso() throws Exception {
        Usuario admin = usuarios.buscarPorEmail(ADMIN);
        Usuario u1 = usuarios.buscarPorEmail(USER01);
        Usuario u2 = usuarios.buscarPorEmail(USER02);

        Indices indices = pastaSegura.carregarIndices(pasta, chaveAdmin(), publicaAdmin(), u1);
        assertEquals(3, indices.index().size());
        assertEquals(1, indices.share().size());
        assertEquals("XXYYZZ22.1.shr", indices.share().get(0).nomeEnvelope());

        assertEquals(List.of("XXYYZZ00"), codigos(pastaSegura.arquivosAutorizados(admin, indices)));
        assertEquals(List.of("XXYYZZ11", "XXYYZZ22"), codigos(pastaSegura.arquivosAutorizados(u1, indices)));
        assertEquals(List.of("XXYYZZ11", "XXYYZZ22"), codigos(pastaSegura.arquivosAutorizados(u2, indices)));

        ArquivoProtegido a11 = indices.index().get(1);
        ArquivoProtegido a22 = indices.index().get(2);
        assertEquals("dono", pastaSegura.origemAcesso(u1, a11, indices.share()));
        assertEquals("compartilhado", pastaSegura.origemAcesso(u1, a22, indices.share()));
        assertEquals("grupo", pastaSegura.origemAcesso(u2, a11, indices.share()));
        assertFalse(pastaSegura.temPermissao(admin, a11, indices.share()));
    }

    @Test
    public void t07_recuperaArquivosPorDonoECompartilhamento() throws Exception {
        Usuario u1 = usuarios.buscarPorEmail(USER01);
        Indices indices = pastaSegura.carregarIndices(pasta, chaveAdmin(), publicaAdmin(), u1);
        PrivateKey chaveU1 = chaves.carregarChavePrivada(chave("user01-pkcs8-aes.key"), "user01");

        // Dono
        Path gravado = pastaSegura.recuperarArquivo(pasta, indices.index().get(1), u1, chaveU1, indices.share());
        assertEquals("teste01.docx", gravado.getFileName().toString());
        assertTrue(Files.size(gravado) > 10000);
        assertEquals("PK", new String(Files.readAllBytes(gravado), 0, 2, "US-ASCII"));

        // Compartilhado (envelope XXYYZZ22.1.shr)
        Path gravado22 = pastaSegura.recuperarArquivo(pasta, indices.index().get(2), u1, chaveU1, indices.share());
        assertEquals("teste02.docx", gravado22.getFileName().toString());
        assertEquals("PK", new String(Files.readAllBytes(gravado22), 0, 2, "US-ASCII"));
    }

    @Test
    public void t08_negaAcessoNaoAutorizado() throws Exception {
        Usuario admin = usuarios.buscarPorEmail(ADMIN);
        Usuario u2 = usuarios.buscarPorEmail(USER02);
        Indices indices = pastaSegura.carregarIndices(pasta, chaveAdmin(), publicaAdmin(), u2);
        ArquivoProtegido a11 = indices.index().get(1);
        Files.deleteIfExists(pasta.resolve("teste01.docx"));

        // Admin nao e dono, nem do grupo "usuario", nem tem compartilhamento
        try {
            pastaSegura.recuperarArquivo(pasta, a11, admin, chaveAdmin(), indices.share());
            fail();
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("nao tem permissao"));
        }

        // user02 ve o arquivo pelo grupo, mas nao existe envelope para ele (sigilo)
        PrivateKey chaveU2 = chaves.carregarChavePrivada(chave("user02-pkcs8-aes.key"), "user02");
        try {
            pastaSegura.recuperarArquivo(pasta, a11, u2, chaveU2, indices.share());
            fail();
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("sigilo"));
        }
        assertFalse("nada deve ser gravado sem verificacao", Files.exists(pasta.resolve("teste01.docx")));
    }

    @Test
    public void t09_detectaArquivosCorrompidos() throws Exception {
        Usuario u1 = usuarios.buscarPorEmail(USER01);
        PrivateKey chaveU1 = chaves.carregarChavePrivada(chave("user01-pkcs8-aes.key"), "user01");
        Path corrompida = Files.createTempDirectory("cofre-corrompida");
        try (var lista = Files.list(FILES)) {
            for (Path p : lista.toList()) {
                Files.copy(p, corrompida.resolve(p.getFileName()), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        Indices indices = pastaSegura.carregarIndices(corrompida, chaveAdmin(), publicaAdmin(), u1);
        ArquivoProtegido a11 = indices.index().get(1);

        // Assinatura adulterada: decripta, mas falha em integridade/autenticidade
        inverterUltimoByte(corrompida.resolve("XXYYZZ11.asd"));
        try {
            pastaSegura.recuperarArquivo(corrompida, a11, u1, chaveU1, indices.share());
            fail();
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("integridade"));
        }
        assertFalse(Files.exists(corrompida.resolve("teste01.docx")));

        // Criptograma adulterado: falha de sigilo ou de integridade, nunca grava
        inverterUltimoByte(corrompida.resolve("XXYYZZ11.enc"));
        try {
            pastaSegura.recuperarArquivo(corrompida, a11, u1, chaveU1, indices.share());
            fail();
        } catch (SecurityException e) {
            // esperado
        }
        assertFalse(Files.exists(corrompida.resolve("teste01.docx")));

        // Indice adulterado: a consulta nao prossegue
        inverterUltimoByte(corrompida.resolve("index.asd"));
        try {
            pastaSegura.carregarIndices(corrompida, chaveAdmin(), publicaAdmin(), u1);
            fail();
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains("index"));
        }

        // Frase secreta errada na consulta (chave privada nao abre)
        try {
            chaves.carregarChavePrivada(chave("user01-pkcs8-aes.key"), "frase-errada");
            fail();
        } catch (Exception e) {
            // esperado
        }
    }

    // ------------------------------------------------------------------
    // Auditoria e logView
    // ------------------------------------------------------------------

    @Test
    public void t10_logViewAutenticaSomenteAdministrador() throws Exception {
        X509Certificate certAdmin = certificados.carregarDePem(
                chaveiro.buscarCertificado(usuarios.buscarPorEmail(ADMIN).getUid()));
        assertTrue(chaves.validarParDeChaves(chaveAdmin(), certAdmin, 2048));

        PrivateKey chaveU1 = chaves.carregarChavePrivada(chave("user01-pkcs8-aes.key"), "user01");
        assertFalse(chaves.validarParDeChaves(chaveU1, certAdmin, 2048));
    }

    @Test
    public void t11_registrosGuardamApenasCodigos() throws Exception {
        List<Registro> registros = new RegistroRepository().listarCronologico();
        assertFalse(registros.isEmpty());

        Set<Integer> mids = new HashSet<>();
        String anterior = "";
        for (Registro r : registros) {
            mids.add(r.mid());
            assertTrue("ordem cronologica", r.dataHora().compareTo(anterior) >= 0);
            anterior = r.dataHora();
        }
        for (int esperado : new int[]{2003, 2004, 2005, 3003, 3004, 3005, 3006, 3007,
                4003, 4004, 4005, 4006, 4007, 6003, 6004, 6005, 6006, 6007,
                7005, 7006, 7008, 7010, 7011, 7015, 7016, 7017, 7018, 7019, 7020, 7021}) {
            assertTrue("faltou o registro " + esperado, mids.contains(esperado));
        }

        // A tabela Registros nao tem coluna de texto
        try (var conexao = br.puc.cofre.database.DatabaseConnection.getConnection();
             var stmt = conexao.createStatement();
             var rs = stmt.executeQuery("PRAGMA table_info(Registros)")) {
            while (rs.next()) {
                String coluna = rs.getString("name");
                assertTrue(coluna, List.of("RID", "MID", "UID", "ARQUIVO", "DATA_HORA").contains(coluna));
            }
        }
    }

    // ------------------------------------------------------------------
    // Apoio
    // ------------------------------------------------------------------

    private static String chave(String nome) {
        return KEYS.resolve(nome).toString();
    }

    private PrivateKey chaveAdmin() throws Exception {
        return chaves.carregarChavePrivada(chave("admin-pkcs8-aes.key"), "admin");
    }

    private PublicKey publicaAdmin() throws Exception {
        return certificados.carregarCertificado(chave("admin-x509.crt")).getPublicKey();
    }

    // Simula os cliques do teclado virtual: cada botao mostra o algarismo da
    // senha junto com outro algarismo diferente.
    private static List<String> pares(String senha) {
        List<String> pares = new ArrayList<>();
        for (char c : senha.toCharArray()) {
            int d = c - '0';
            int outro = (d + 3) % 10;
            pares.add(d < outro ? d + " ou " + outro : outro + " ou " + d);
        }
        return pares;
    }

    private static List<String> codigos(List<ArquivoProtegido> lista) {
        List<String> nomes = new ArrayList<>();
        for (ArquivoProtegido a : lista) {
            nomes.add(a.nomeCodigo());
        }
        return nomes;
    }

    private static void inverterUltimoByte(Path arquivo) throws Exception {
        byte[] dados = Files.readAllBytes(arquivo);
        dados[dados.length - 1] ^= (byte) 0xFF;
        Files.write(arquivo, dados);
    }
}
