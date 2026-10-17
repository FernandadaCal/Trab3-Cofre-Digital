/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.view;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

/** Teclado sobrecarregado: cinco botoes, dois algarismos por botao. */
public class TecladoVirtual extends JDialog {
    private final List<String> paresEscolhidos = new ArrayList<>();
    private final JButton[] botoes = new JButton[5];
    private final JLabel status = new JLabel("Cliques: 0 (minimo 8, maximo 10)");
    private final SecureRandom aleatorio = new SecureRandom();
    private boolean confirmado = false;

    public TecladoVirtual() {
        setTitle("Cofre Digital - Senha");
        setModal(true);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());
        JPanel painel = new JPanel(new GridLayout(1, 5, 5, 5));
        for (int i = 0; i < 5; i++) {
            botoes[i] = new JButton();
            final int indice = i;
            botoes[i].addActionListener(e -> {
                if (paresEscolhidos.size() < 10) {
                    paresEscolhidos.add(botoes[indice].getText());
                    status.setText("Cliques: " + paresEscolhidos.size());
                    embaralhar();
                }
            });
            painel.add(botoes[i]);
        }
        JPanel rodape = new JPanel();
        JButton apagar = new JButton("Apagar tudo");
        apagar.addActionListener(e -> {
            paresEscolhidos.clear();
            status.setText("Cliques: 0");
            embaralhar();
        });
        JButton confirmar = new JButton("Confirmar");
        confirmar.addActionListener(e -> {
            if (paresEscolhidos.size() >= 8 && paresEscolhidos.size() <= 10) {
                confirmado = true;
                dispose();
            }
        });
        rodape.add(apagar);
        rodape.add(confirmar);
        add(status, BorderLayout.NORTH);
        add(painel, BorderLayout.CENTER);
        add(rodape, BorderLayout.SOUTH);
        embaralhar();
        setSize(650, 150);
        setLocationRelativeTo(null);
    }

    private void embaralhar() {
        List<Integer> digitos = new ArrayList<>();
        for (int i = 0; i < 10; i++) digitos.add(i);
        // Randomizacao segura a cada clique.
        for (int i = 9; i > 0; i--) {
            int j = aleatorio.nextInt(i + 1);
            Collections.swap(digitos, i, j);
        }
        for (int i = 0; i < 5; i++) {
            botoes[i].setText(digitos.get(2 * i) + " ou " + digitos.get(2 * i + 1));
        }
    }

    /** Pares escolhidos; nao equivalem a uma senha em texto plano. */
    public List<String> obterParesEscolhidos() {
        return confirmado ? List.copyOf(paresEscolhidos) : List.of();
    }

    public static List<String> solicitarPares() {
        if (SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException("Chame a partir de uma thread fora da interface.");
        }
        TecladoVirtual teclado = new TecladoVirtual();
        teclado.setVisible(true);
        return teclado.obterParesEscolhidos();
    }
}
