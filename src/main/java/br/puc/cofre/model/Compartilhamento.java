/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.model;

/**
 * Uma linha do arquivo share decriptado:
 * NOME_CODIGO ID_COMPARTILHAMENTO USUARIO_AUTORIZADO
 */
public record Compartilhamento(String nomeCodigo, int id, String usuarioAutorizado) {

    // Nome do envelope que protege a semente deste compartilhamento.
    public String nomeEnvelope() {
        return nomeCodigo + "." + id + ".shr";
    }
}
