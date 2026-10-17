/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.view;

import br.puc.cofre.model.Usuario;

import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/**
 * Tela de Cadastro. A janela so cuida dos campos e botoes; a validacao, a
 * confirmacao e a gravacao ficam no CofreDigitalService, acessado pelas Acoes.
 */
public class TelaCadastro extends JDialog {

    /** O que a tela pede ao servico quando um botao e pressionado. */
    public interface Acoes {
        int totalUsuarios() throws Exception;

        // Devolve true quando o cadastro foi efetivado (o formulario e limpo).
        boolean cadastrar(String caminhoCertificado, String caminhoChave, String frase,
                          int gid, String senha, String confirmacao) throws Exception;

        void voltar();
    }

    private final Acoes acoes;
    private final boolean cadastroInicial;

    private final JLabel total = new JLabel();
    private final JTextField caminhoCertificado = new JTextField(40);
    private final JTextField caminhoChave = new JTextField(40);
    private final JPasswordField frase = new JPasswordField(40);
    private final JComboBox<String> grupo = new JComboBox<>(new String[] {"Administrador", "Usuario"});
    private final JPasswordField senha = new JPasswordField(40);
    private final JPasswordField confirmacao = new JPasswordField(40);

    // operador: quem esta cadastrando (null no cadastro inicial do administrador).
    // No cadastro inicial o grupo e fixo em Administrador e a tela fecha ao efetivar.
    private TelaCadastro(Usuario operador, boolean cadastroInicial, Acoes acoes) {
        super((Frame) null, "Cofre Digital - Tela de Cadastro", true);
        this.acoes = acoes;
        this.cadastroInicial = cadastroInicial;
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel cabecalho = Componentes.cabecalho(operador, null);
        cabecalho.add(total);
        atualizarTotal();

        JPanel formulario = Componentes.formulario();
        Componentes.linha(formulario, "Caminho do arquivo do certificado digital:", caminhoCertificado);
        Componentes.linha(formulario, "Caminho do arquivo da chave privada:", caminhoChave);
        Componentes.linha(formulario, "Frase secreta:", frase);
        Componentes.linha(formulario, "Grupo:", grupo);
        Componentes.linha(formulario, "Senha pessoal (8 a 10 algarismos):", senha);
        Componentes.linha(formulario, "Confirmacao senha pessoal:", confirmacao);
        grupo.setSelectedIndex(cadastroInicial ? 0 : 1);
        grupo.setEnabled(!cadastroInicial);

        JButton cadastrar = new JButton("Cadastrar");
        JButton voltar = new JButton(cadastroInicial ? "Encerrar Sistema" : "Voltar para o Menu Principal");
        cadastrar.addActionListener(e -> cadastrar());
        voltar.addActionListener(e -> voltar());
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                voltar();
            }
        });

        JPanel botoes = new JPanel();
        botoes.add(cadastrar);
        botoes.add(voltar);
        getRootPane().setDefaultButton(cadastrar);
        add(cabecalho, BorderLayout.NORTH);
        add(formulario, BorderLayout.CENTER);
        add(botoes, BorderLayout.SOUTH);
        pack();
        setLocationRelativeTo(null);
    }

    public static void mostrar(Usuario operador, boolean cadastroInicial, Acoes acoes) {
        new TelaCadastro(operador, cadastroInicial, acoes).setVisible(true);
    }

    private void cadastrar() {
        try {
            boolean efetivado = acoes.cadastrar(caminhoCertificado.getText().trim(),
                    caminhoChave.getText().trim(), new String(frase.getPassword()),
                    grupo.getSelectedIndex() + 1, new String(senha.getPassword()),
                    new String(confirmacao.getPassword()));
            if (efetivado && cadastroInicial) {
                dispose();
                return;
            }
            // Cadastro feito: formulario vazio. Falhou: mantem caminhos e grupo,
            // mas as senhas e a frase precisam ser digitadas de novo.
            if (efetivado) {
                caminhoCertificado.setText("");
                caminhoChave.setText("");
                grupo.setSelectedIndex(1);
            }
            frase.setText("");
            senha.setText("");
            confirmacao.setText("");
            atualizarTotal();
        } catch (Exception e) {
            Componentes.mostrarErro("Cadastro nao realizado", e.getMessage());
        }
    }

    private void voltar() {
        acoes.voltar();
        dispose();
    }

    private void atualizarTotal() {
        try {
            total.setText("Total de usuarios do sistema: " + acoes.totalUsuarios());
        } catch (Exception e) {
            total.setText("Total de usuarios do sistema: indisponivel");
        }
    }

    // Tela de confirmacao com os campos do certificado. Devolve true se o operador confirmou.
    public static boolean confirmarCertificado(String descricaoCertificado, String grupo) {
        JTextArea texto = new JTextArea(descricaoCertificado + "\nGrupo: " + grupo);
        texto.setEditable(false);
        int opcao = JOptionPane.showOptionDialog(null, new JScrollPane(texto),
                "Confirme os dados do certificado digital", JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE, null, new String[] {"Confirmar", "Rejeitar"}, "Confirmar");
        return opcao == 0;
    }

    // Mostra o segredo que o usuario precisa cadastrar no Google Authenticator.
    public static void mostrarSegredo(String nome, String email, int uid, String segredoBase32) {
        JTextArea texto = new JTextArea("Usuario cadastrado: " + nome
                + " (login " + email + ", UID " + uid + ").\n\n"
                + "Cadastre este segredo no Google Authenticator (chave em BASE32):\n"
                + segredoBase32 + "\n\n"
                + "otpauth://totp/Cofre%20Digital:" + email + "?secret=" + segredoBase32);
        texto.setEditable(false);
        texto.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JOptionPane.showMessageDialog(null, texto, "Cadastro realizado", JOptionPane.INFORMATION_MESSAGE);
    }
}
