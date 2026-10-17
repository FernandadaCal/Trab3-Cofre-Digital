/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.service;

import br.puc.cofre.database.RegistroRepository;
import br.puc.cofre.model.Usuario;
import java.sql.SQLException;

/**
 * Ponto unico de registro dos eventos de auditoria.
 * Recebe apenas o codigo MID da Tabela de Mensagens de Registro; o texto
 * nunca e gravado na tabela Registros.
 */
public class Auditoria {

    private static final RegistroRepository registros = new RegistroRepository();

    // Evento sem usuario identificado (ex.: 1001, 2001, 2005).
    public static void registrar(int mid) {
        gravar(mid, null, null);
    }

    // Evento associado a um usuario (ex.: 2003, 3003, 5001).
    public static void registrar(int mid, Usuario usuario) {
        gravar(mid, usuario == null ? null : usuario.getUid(), null);
    }

    // Evento associado a um usuario e a um arquivo da pasta segura (7015 a 7021).
    public static void registrar(int mid, Usuario usuario, String arquivo) {
        gravar(mid, usuario == null ? null : usuario.getUid(), arquivo);
    }

    private static void gravar(int mid, Integer uid, String arquivo) {
        try {
            registros.inserir(mid, uid, arquivo);
        } catch (SQLException e) {
            // A falha de auditoria nao pode derrubar o sistema, mas precisa ficar visivel.
            System.err.println("[AUDITORIA] Falha ao gravar registro " + mid + ": " + e.getMessage());
        }
    }
}
