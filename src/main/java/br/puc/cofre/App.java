/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre;

import br.puc.cofre.database.DatabaseInitializer;
import br.puc.cofre.database.MensagemInitializer;
import br.puc.cofre.service.CofreDigitalService;
import br.puc.cofre.view.Componentes;

/** Ponto de entrada do Cofre Digital. */
public class App {
    public static void main(String[] args) {
        try {
            DatabaseInitializer.initialize();
            MensagemInitializer.initialize();
            new CofreDigitalService().executar();
        } catch (Exception e) {
            // Falha na partida (ex.: frase do administrador errada) encerra o programa.
            System.err.println("Cofre Digital encerrado: " + e.getMessage());
            Componentes.mostrarErro("Cofre Digital encerrado", e.getMessage());
            System.exit(1);
        }
        // As janelas Swing deixam threads vivas; encerra a JVM explicitamente.
        System.exit(0);
    }
}
