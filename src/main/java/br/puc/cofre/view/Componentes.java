/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.view;

import br.puc.cofre.model.Usuario;

import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.GridLayout;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

/** Pedacos de tela usados por varias janelas: cabecalho, formulario e avisos. */
public class Componentes {

    private Componentes() {}

    // Cabecalho comum das telas (login, grupo e nome) seguido de uma linha com um total.
    public static JPanel cabecalho(Usuario usuario, String linhaTotal) {
        JPanel painel = new JPanel(new GridLayout(0, 1));
        painel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        if (usuario != null) {
            painel.add(new JLabel("Login: " + usuario.getEmail()));
            painel.add(new JLabel("Grupo: " + usuario.getNomeGrupo()));
            painel.add(new JLabel("Nome: " + usuario.getNome()));
        }
        if (linhaTotal != null) {
            painel.add(new JLabel(" "));
            painel.add(new JLabel(linhaTotal));
        }
        return painel;
    }

    // Painel de formulario com duas colunas: rotulo e campo.
    public static JPanel formulario() {
        JPanel painel = new JPanel(new GridLayout(0, 2, 8, 8));
        painel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        return painel;
    }

    public static void linha(JPanel formulario, String rotulo, JComponent campo) {
        formulario.add(new JLabel(rotulo));
        formulario.add(campo);
    }

    // Janela modal sem fechamento automatico: cada tela decide o que fazer no "X".
    public static JDialog janela(String titulo) {
        JDialog dialogo = new JDialog((Frame) null, titulo, true);
        dialogo.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        dialogo.setLayout(new BorderLayout());
        return dialogo;
    }

    public static void mostrarInfo(String titulo, String mensagem) {
        JOptionPane.showMessageDialog(null, mensagem, titulo, JOptionPane.INFORMATION_MESSAGE);
    }

    public static void mostrarErro(String titulo, String mensagem) {
        JOptionPane.showMessageDialog(null, mensagem, titulo, JOptionPane.ERROR_MESSAGE);
    }

    // Aviso sem botoes para operacoes demoradas (ex.: conferencia da senha com BCrypt).
    // Quem chama fecha a janela com dispose().
    public static JDialog aguarde(String mensagem) {
        JDialog dialogo = new JDialog((Frame) null, "Cofre Digital", false);
        dialogo.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        JLabel texto = new JLabel(mensagem);
        texto.setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30));
        dialogo.add(texto);
        dialogo.pack();
        dialogo.setLocationRelativeTo(null);
        dialogo.setVisible(true);
        return dialogo;
    }
}
