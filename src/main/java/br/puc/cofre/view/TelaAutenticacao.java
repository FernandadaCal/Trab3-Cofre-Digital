/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.view;

import br.puc.cofre.model.Usuario;

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * Etapas 1 e 3 da autenticacao (login name e codigo TOTP).
 * A etapa 2 e o TecladoVirtual, que ja existia.
 */
public class TelaAutenticacao {

    private TelaAutenticacao() {}

    // Etapa 1. Devolve o e-mail digitado, ou null para encerrar o sistema.
    public static String pedirLogin() {
        JDialog dialogo = Componentes.janela("Cofre Digital - Autenticacao (etapa 1)");
        String[] resposta = new String[1];

        JTextField email = new JTextField(30);
        JPanel formulario = Componentes.formulario();
        Componentes.linha(formulario, "Login name (e-mail):", email);

        JButton continuar = new JButton("Continuar");
        JButton encerrar = new JButton("Encerrar Sistema");
        continuar.addActionListener(e -> {
            resposta[0] = email.getText().trim();
            dialogo.dispose();
        });
        encerrar.addActionListener(e -> dialogo.dispose());
        // Fechar a janela equivale a encerrar o sistema: nao ha como seguir sem login.
        dialogo.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dialogo.dispose();
            }
        });

        JPanel botoes = new JPanel();
        botoes.add(continuar);
        botoes.add(encerrar);
        dialogo.getRootPane().setDefaultButton(continuar);
        dialogo.add(formulario, BorderLayout.CENTER);
        dialogo.add(botoes, BorderLayout.SOUTH);
        dialogo.pack();
        dialogo.setLocationRelativeTo(null);
        dialogo.setVisible(true);
        return resposta[0];
    }

    // Etapa 3. Devolve o codigo digitado, ou null para voltar a etapa 1.
    public static String pedirToken(Usuario usuario) {
        JDialog dialogo = Componentes.janela("Cofre Digital - Autenticacao (etapa 3)");
        String[] resposta = new String[1];

        JTextField codigo = new JTextField(10);
        JPanel formulario = Componentes.formulario();
        formulario.add(new JLabel("Login:"));
        formulario.add(new JLabel(usuario.getEmail()));
        Componentes.linha(formulario, "Codigo do Google Authenticator (6 digitos):", codigo);

        JButton validar = new JButton("Validar");
        JButton voltar = new JButton("Voltar a etapa 1");
        validar.addActionListener(e -> {
            resposta[0] = codigo.getText().trim();
            dialogo.dispose();
        });
        voltar.addActionListener(e -> dialogo.dispose());
        dialogo.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dialogo.dispose();
            }
        });

        JPanel botoes = new JPanel();
        botoes.add(validar);
        botoes.add(voltar);
        dialogo.getRootPane().setDefaultButton(validar);
        dialogo.add(formulario, BorderLayout.CENTER);
        dialogo.add(botoes, BorderLayout.SOUTH);
        dialogo.pack();
        dialogo.setLocationRelativeTo(null);
        dialogo.setVisible(true);
        return resposta[0];
    }
}
