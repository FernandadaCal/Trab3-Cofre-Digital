/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Gera o segredo TOTP e protege sua representacao Base32 no banco. */
public class TokenService {

    public String gerarSegredoBase32() {
        byte[] segredo = new byte[20];
        new SecureRandom().nextBytes(segredo);
        Base32 base32 = new Base32(Base32.Alphabet.BASE32, false, false);
        return base32.toString(segredo);
    }

    private SecretKey derivarChave(String senhaPessoal) throws Exception {
        if (senhaPessoal == null || senhaPessoal.isEmpty()) {
            throw new IllegalArgumentException("Senha pessoal obrigatoria.");
        }
        // Compatibilidade com o esquema SHA1PRNG exigido no enunciado.
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(senhaPessoal.getBytes(StandardCharsets.UTF_8));
        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256, random);
        return gerador.generateKey();
    }

    public String criptografarSegredo(String segredoBase32, String senhaPessoal)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, derivarChave(senhaPessoal));
        byte[] cifrado = cipher.doFinal(segredoBase32.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cifrado);
    }

    public String descriptografarSegredo(String valorArmazenado, String senhaPessoal)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, derivarChave(senhaPessoal));
        byte[] decifrado = cipher.doFinal(Base64.getDecoder().decode(valorArmazenado));
        return new String(decifrado, StandardCharsets.UTF_8);
    }
}
