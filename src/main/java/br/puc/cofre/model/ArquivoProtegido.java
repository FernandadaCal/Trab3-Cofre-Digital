/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.model;

/**
 * Uma linha do arquivo index decriptado:
 * NOME_CODIGO NOME_SECRETO DONO GRUPO
 */
public record ArquivoProtegido(String nomeCodigo, String nomeSecreto,
                               String dono, String grupo) {
}
