/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

/** Teste manual do hash BCrypt da senha pessoal. */
public class TesteSenha {

    public static void main(String[] args) {

        SenhaService service = new SenhaService();

        String senha = "13572468";
        String hash = service.gerarHash(senha);

        System.out.println("Hash gerado: " + hash);

        System.out.println("Senha correta: "
                + service.verificarSenha(senha, hash));

        System.out.println("Senha incorreta: "
                + service.verificarSenha("87654321", hash));

        System.out.println("Senha repetida aceita: "
                + service.validarFormato("11111111"));
    }
}
