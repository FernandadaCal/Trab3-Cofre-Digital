/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.view;

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

/**
 * Partida do sistema (da segunda execucao em diante): pede a frase secreta da
 * chave privada do administrador. Na primeira execucao a TelaCadastro e usada.
 */
public class TelaInicializacao {

    private TelaInicializacao() {}

    // Devolve a frase digitada, ou null se o operador pediu para encerrar.
    public static String pedirFraseAdministrador(String emailAdmin) {
        JDialog dialogo = Componentes.janela("Cofre Digital - Partida do sistema");
        String[] resposta = new String[1];

        JPasswordField frase = new JPasswordField(25);
        JPanel formulario = Componentes.formulario();
        formulario.add(new JLabel("Administrador do sistema:"));
        formulario.add(new JLabel(emailAdmin));
        Componentes.linha(formulario, "Frase secreta da chave privada:", frase);

        JButton validar = new JButton("Validar");
        JButton encerrar = new JButton("Encerrar Sistema");
        validar.addActionListener(e -> {
            resposta[0] = new String(frase.getPassword());
            dialogo.dispose();
        });
        encerrar.addActionListener(e -> dialogo.dispose());
        dialogo.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dialogo.dispose();
            }
        });

        JPanel botoes = new JPanel();
        botoes.add(validar);
        botoes.add(encerrar);
        dialogo.getRootPane().setDefaultButton(validar);
        dialogo.add(formulario, BorderLayout.CENTER);
        dialogo.add(botoes, BorderLayout.SOUTH);
        dialogo.pack();
        dialogo.setLocationRelativeTo(null);
        dialogo.setVisible(true);
        return resposta[0];
    }
}
