/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import br.puc.cofre.security.Base32;
import br.puc.cofre.security.SenhaService;
import br.puc.cofre.security.TOTP;
import br.puc.cofre.security.TokenService;
import br.puc.cofre.view.TecladoVirtual;

import java.awt.GraphicsEnvironment;
import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.JButton;
import javax.swing.SwingUtilities;
import org.junit.Assume;
import org.junit.Test;

/** Testes unitarios que nao dependem do banco nem do pacote do professor. */
public class SegurancaUnitariaTest {

    private final SenhaService senhas = new SenhaService();

    @Test
    public void senhaPessoalSegueAsRegrasDoEnunciado() {
        assertTrue(senhas.validarFormato("13572468"));
        assertTrue(senhas.validarFormato("135724689"));
        assertTrue(senhas.validarFormato("1357246890"));
        assertFalse("menos de 8", senhas.validarFormato("1357246"));
        assertFalse("mais de 10", senhas.validarFormato("13572468901"));
        assertFalse("letras", senhas.validarFormato("1357246a"));
        assertFalse("todos iguais", senhas.validarFormato("11111111"));
        assertFalse("repetido em sequencia", senhas.validarFormato("12345566"));
        assertFalse(senhas.validarFormato(null));
    }

    @Test
    public void hashBcryptVersao2yCusto08() {
        String hash = senhas.gerarHash("13572468");
        assertTrue(hash.startsWith("$2y$08$"));
        assertEquals(60, hash.length());
        assertTrue(senhas.verificarSenha("13572468", hash));
        assertFalse(senhas.verificarSenha("13572469", hash));
        // Exemplo do enunciado
        assertTrue(senhas.verificarSenha("13572468",
                "$2y$08$ajDZdV0XFoYiLRE0ZrSx6OmRbhhB5qM.Ap6c.0LqRu2cIY1jpytuO"));
    }

    @Test
    public void totpAceitaJanelaDeUmIntervalo() throws Exception {
        String segredo = new TokenService().gerarSegredoBase32();
        assertEquals(32, segredo.length());
        assertEquals(20, new Base32(Base32.Alphabet.BASE32, false, false).fromString(segredo).length);

        TOTP totp = new TOTP(segredo, 30);
        String codigo = totp.generateCode();
        assertTrue(codigo.matches("[0-9]{6}"));
        assertTrue(totp.validateCode(codigo));
        assertFalse(totp.validateCode("12345"));
        assertFalse(totp.validateCode(codigo.equals("000000") ? "111111" : "000000"));

        // Vetor do RFC 6238 (chave "12345678901234567890", T = 59 s -> contador 1)
        TOTP rfc = new TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30);
        java.lang.reflect.Method m = TOTP.class.getDeclaredMethod("TOTPCode", long.class);
        m.setAccessible(true);
        assertEquals("287082", m.invoke(rfc, 1L));
    }

    @Test
    public void segredoTotpCifradoComAesDaSenhaPessoal() throws Exception {
        TokenService tokens = new TokenService();
        String segredo = tokens.gerarSegredoBase32();
        String cifrado = tokens.criptografarSegredo(segredo, "13572468");
        assertFalse(cifrado.contains(segredo));
        assertEquals(segredo, tokens.descriptografarSegredo(cifrado, "13572468"));
        try {
            tokens.descriptografarSegredo(cifrado, "87654321");
            // Com senha errada o padding quase sempre falha; se nao falhar, o texto nao confere.
        } catch (Exception esperado) {
            return;
        }
        assertFalse(segredo.equals(tokens.descriptografarSegredo(cifrado, "87654321")));
    }

    @Test
    public void tecladoVirtualTemCincoBotoesComDezAlgarismosRedistribuidos() throws Exception {
        Assume.assumeFalse("sem ambiente grafico", GraphicsEnvironment.isHeadless());

        TecladoVirtual teclado = new TecladoVirtual();
        Field campo = TecladoVirtual.class.getDeclaredField("botoes");
        campo.setAccessible(true);
        JButton[] botoes = (JButton[]) campo.get(teclado);
        assertEquals(5, botoes.length);

        Set<String> distribuicoes = new HashSet<>();
        for (int clique = 0; clique < 12; clique++) {
            Set<Character> digitos = new HashSet<>();
            StringBuilder distribuicao = new StringBuilder();
            for (JButton botao : botoes) {
                String texto = botao.getText();
                assertTrue(texto, texto.matches("[0-9] ou [0-9]"));
                digitos.add(texto.charAt(0));
                digitos.add(texto.charAt(5));
                distribuicao.append(texto).append('|');
            }
            assertEquals("dez algarismos sem repeticao", 10, digitos.size());
            distribuicoes.add(distribuicao.toString());
            SwingUtilities.invokeAndWait(botoes[clique % 5]::doClick);
        }
        assertTrue("os algarismos devem ser redistribuidos a cada clique", distribuicoes.size() > 1);

        // Sem confirmar, nada e devolvido
        List<String> pares = teclado.obterParesEscolhidos();
        assertTrue(pares.isEmpty());
        teclado.dispose();
    }
}
