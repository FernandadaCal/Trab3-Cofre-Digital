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

/** Tela Principal: cabecalho, total de acessos e o menu com os botoes. */
public class TelaPrincipal {

    public static final int CADASTRAR = 1;
    public static final int CONSULTAR = 2;
    public static final int SAIR = 3;

    private TelaPrincipal() {}

    // Devolve a opcao escolhida (CADASTRAR, CONSULTAR ou SAIR).
    public static int mostrar(Usuario usuario) {
        JDialog dialogo = Componentes.janela("Cofre Digital - Tela Principal");
        int[] resposta = {SAIR};

        JPanel menu = new JPanel(new GridLayout(0, 1, 5, 5));
        menu.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
        menu.add(new JLabel("Menu Principal:"));

        // O cadastro de usuarios e exclusivo do grupo Administrador.
        if (usuario.getGid() == 1) {
            JButton cadastrar = new JButton("1 - Cadastrar um novo usuario");
            cadastrar.addActionListener(e -> {
                resposta[0] = CADASTRAR;
                dialogo.dispose();
            });
            menu.add(cadastrar);
        }
        JButton consultar = new JButton("2 - Consultar pasta de arquivos secretos do usuario");
        consultar.addActionListener(e -> {
            resposta[0] = CONSULTAR;
            dialogo.dispose();
        });
        JButton sair = new JButton("3 - Sair do Sistema");
        sair.addActionListener(e -> dialogo.dispose());
        menu.add(consultar);
        menu.add(sair);

        // Fechar a janela leva a Tela de Saida, como o botao Sair.
        dialogo.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dialogo.dispose();
            }
        });

        dialogo.add(Componentes.cabecalho(usuario,
                "Total de acessos do usuario: " + usuario.getTotalAcessos()), BorderLayout.NORTH);
        dialogo.add(menu, BorderLayout.CENTER);
        dialogo.pack();
        dialogo.setLocationRelativeTo(null);
        dialogo.setVisible(true);
        return resposta[0];
    }
}
