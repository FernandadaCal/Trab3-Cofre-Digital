/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.view;

import br.puc.cofre.model.Usuario;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;

/** Tela de Saida: confirma o encerramento da sessao ou do sistema. */
public class TelaSaida {

    public static final int ENCERRAR_SESSAO = 1;
    public static final int ENCERRAR_SISTEMA = 2;
    public static final int VOLTAR = 3;

    private TelaSaida() {}

    public static int mostrar(Usuario usuario) {
        JDialog dialogo = Componentes.janela("Cofre Digital - Tela de Saida");
        int[] resposta = {VOLTAR};

        JPanel corpo = new JPanel(new GridLayout(0, 1, 5, 5));
        corpo.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
        corpo.add(new JLabel("Saida do sistema:"));
        corpo.add(new JLabel("Pressione o botao Encerrar Sessao ou o botao Encerrar Sistema para confirmar."));

        JButton sessao = new JButton("Encerrar Sessao");
        JButton sistema = new JButton("Encerrar Sistema");
        JButton voltar = new JButton("Voltar para o Menu Principal");
        sessao.addActionListener(e -> {
            resposta[0] = ENCERRAR_SESSAO;
            dialogo.dispose();
        });
        sistema.addActionListener(e -> {
            resposta[0] = ENCERRAR_SISTEMA;
            dialogo.dispose();
        });
        voltar.addActionListener(e -> dialogo.dispose());
        // Fechar a janela equivale a voltar ao menu.
        dialogo.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dialogo.dispose();
            }
        });
        corpo.add(sessao);
        corpo.add(sistema);
        corpo.add(voltar);

        dialogo.add(Componentes.cabecalho(usuario,
                "Total de acessos do usuario: " + usuario.getTotalAcessos()), BorderLayout.NORTH);
        dialogo.add(corpo, BorderLayout.CENTER);
        dialogo.pack();
        dialogo.setLocationRelativeTo(null);
        dialogo.setVisible(true);
        return resposta[0];
    }
}
