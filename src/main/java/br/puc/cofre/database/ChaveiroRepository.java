/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Acesso a tabela Chaveiro (chave privada cifrada e certificado de cada usuario). */
public class ChaveiroRepository {

    public int inserir(
            int uid,
            byte[] chavePrivadaCriptografada,
            String certificado,
            Connection connection) throws SQLException {

        String sql = """
            INSERT INTO Chaveiro (UID, CHAVE_PRIVADA, CERTIFICADO)
            VALUES (?, ?, ?)
        """;

        try (PreparedStatement statement = connection.prepareStatement(
                sql, Statement.RETURN_GENERATED_KEYS)) {

            statement.setInt(1, uid);
            statement.setBytes(2, chavePrivadaCriptografada);
            statement.setString(3, certificado);

            statement.executeUpdate();

            try (ResultSet keys = statement.getGeneratedKeys()) {

                if (keys.next()) {
                    return keys.getInt(1);
                }
            }
        }

        throw new SQLException("Nao foi possivel obter o KID.");
    }

    public byte[] buscarChavePrivada(int uid) throws SQLException {

        String sql = """
            SELECT CHAVE_PRIVADA
            FROM Chaveiro
            WHERE UID = ?
        """;

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, uid);

            try (ResultSet result = statement.executeQuery()) {

                if (result.next()) {
                    return result.getBytes("CHAVE_PRIVADA");
                }
            }
        }

        return null;
    }

    public String buscarCertificado(int uid) throws SQLException {

        String sql = """
            SELECT CERTIFICADO
            FROM Chaveiro
            WHERE UID = ?
        """;

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, uid);

            try (ResultSet result = statement.executeQuery()) {

                if (result.next()) {
                    return result.getString("CERTIFICADO");
                }
            }
        }

        return null;
    }

    // Certificado pelo login name: da a chave publica do dono de um arquivo da pasta segura.
    public String buscarCertificadoPorEmail(String email) throws SQLException {

        String sql = """
            SELECT c.CERTIFICADO
            FROM Chaveiro c
            JOIN Usuarios u ON u.UID = c.UID
            WHERE u.EMAIL = ?
        """;

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, email);

            try (ResultSet result = statement.executeQuery()) {

                if (result.next()) {
                    return result.getString("CERTIFICADO");
                }
            }
        }

        return null;
    }
}
