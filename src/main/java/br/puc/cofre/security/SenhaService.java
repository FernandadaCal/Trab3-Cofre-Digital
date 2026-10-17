/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

/** Regras e hash BCrypt da senha pessoal. */
public class SenhaService {

    private static final int CUSTO = 8;
    private static final SecureRandom RANDOM = new SecureRandom();

    // Verifica as regras da senha exigidas pelo professor:
    // 8 a 10 algarismos e sem sequencias de numeros repetidos
    // (dois algarismos iguais seguidos, como "11" ou "000", sao rejeitados).
    public boolean validarFormato(String senha) {

        if (senha == null || !senha.matches("[0-9]{8,10}")) {
            return false;
        }

        for (int i = 1; i < senha.length(); i++) {
            if (senha.charAt(i) == senha.charAt(i - 1)) {
                return false;
            }
        }

        return true;
    }

    // Gera o hash BCrypt, versao 2y e custo 08.
    public String gerarHash(String senha) {

        if (!validarFormato(senha)) {
            throw new IllegalArgumentException(
                "A senha deve ter de 8 a 10 digitos numericos "
                + "e nao pode ter numeros repetidos em sequencia."
            );
        }

        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        return OpenBSDBCrypt.generate(
            "2y", senha.toCharArray(), salt, CUSTO
        );
    }

    // Verifica uma senha informada contra o hash armazenado.
    public boolean verificarSenha(String senha, String hash) {

        if (senha == null || hash == null) {
            return false;
        }

        return OpenBSDBCrypt.checkPassword(
            hash, senha.toCharArray()
        );
    }
}
