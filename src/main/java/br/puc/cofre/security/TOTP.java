/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

/** TOTP (RFC 6238): HMAC-SHA1, 6 digitos, intervalo de 30 s, aceita +-1 intervalo. */
public class TOTP {

    private byte[] key;
    private long timeStepInSeconds = 30;

    public TOTP(String base32EncodedSecret, long timeStepInSeconds)
            throws Exception {

        if (timeStepInSeconds <= 0) {
            throw new Exception("Intervalo de tempo invalido.");
        }

        Base32 base32 = new Base32(
                Base32.Alphabet.BASE32, false, false
        );

        this.key = base32.fromString(base32EncodedSecret);

        if (this.key == null || this.key.length != 20) {
            throw new Exception("Segredo TOTP invalido.");
        }

        this.timeStepInSeconds = timeStepInSeconds;
    }

    // Converte o hash HMAC-SHA1 em um codigo de 6 digitos.
    private String getTOTPCodeFromHash(byte[] hash) {

        int offset = hash[hash.length - 1] & 0x0F;

        int codigoBinario =
                ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);

        int codigo = codigoBinario % 1000000;

        String resultado = Integer.toString(codigo);

        while (resultado.length() < 6) {
            resultado = "0" + resultado;
        }

        return resultado;
    }

    // Calcula HMAC-SHA1 utilizando o contador e a chave secreta.
    private byte[] HMAC_SHA1(byte[] counter, byte[] keyByteArray) {

        try {
            Mac mac = Mac.getInstance("HmacSHA1");

            SecretKeySpec secretKey = new SecretKeySpec(
                    keyByteArray, "HmacSHA1"
            );

            mac.init(secretKey);

            return mac.doFinal(counter);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Erro ao calcular HMAC-SHA1.", e
            );
        }
    }

    // Produz o codigo TOTP para determinado intervalo.
    private String TOTPCode(long timeInterval) {

        byte[] counter = new byte[8];

        for (int i = 7; i >= 0; i--) {
            counter[i] = (byte) (timeInterval & 0xFF);
            timeInterval >>= 8;
        }

        byte[] hash = HMAC_SHA1(counter, key);

        return getTOTPCodeFromHash(hash);
    }

    // Gera o codigo correspondente ao momento atual.
    public String generateCode() {

        long tempoAtual = new Date().getTime() / 1000;

        long intervalo = tempoAtual / timeStepInSeconds;

        return TOTPCode(intervalo);
    }

    // Valida o codigo, aceitando 30 segundos antes ou depois.
    public boolean validateCode(String inputTOTP) {

        if (inputTOTP == null
                || !inputTOTP.matches("[0-9]{6}")) {
            return false;
        }

        long tempoAtual = new Date().getTime() / 1000;

        long intervalo = tempoAtual / timeStepInSeconds;

        for (long i = -1; i <= 1; i++) {

            String codigoEsperado = TOTPCode(intervalo + i);

            if (codigoEsperado.equals(inputTOTP)) {
                return true;
            }
        }

        return false;
    }
}
