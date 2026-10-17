/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.security.SecureRandom;

/** Teste manual do gerador TOTP. */
public class TesteTOTP {

    public static void main(String[] args) {

        try {
            byte[] segredo = new byte[20];

            SecureRandom random = new SecureRandom();
            random.nextBytes(segredo);

            Base32 base32 = new Base32(
                    Base32.Alphabet.BASE32, false, false
            );

            String segredoBase32 = base32.toString(segredo);

            TOTP totp = new TOTP(segredoBase32, 30);

            String codigo = totp.generateCode();

            System.out.println("Segredo Base32: " + segredoBase32);
            System.out.println("Codigo TOTP: " + codigo);

            System.out.println("Codigo valido: "
                    + totp.validateCode(codigo));

            System.out.println("Codigo incorreto: "
                    + totp.validateCode("abcdef"));

        } catch (Exception e) {
            System.err.println("Erro no teste TOTP:");
            System.err.println(e.getMessage());
        }
    }
}
