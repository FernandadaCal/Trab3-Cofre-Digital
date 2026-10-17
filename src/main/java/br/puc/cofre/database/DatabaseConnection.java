/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/** Conexao com o SQLite. */
public class DatabaseConnection {

    // Arquivo do banco. A propriedade -Dcofre.db=... permite apontar para outro
    // arquivo (os testes automatizados usam um banco separado em target/).
    public static String caminhoDoBanco() {
        return System.getProperty("cofre.db", "cofre.db");
    }

    public static Connection getConnection() throws SQLException {

        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + caminhoDoBanco());

        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
        } catch (SQLException e) {
            connection.close();
            throw e;
        }

        return connection;
    }
}
