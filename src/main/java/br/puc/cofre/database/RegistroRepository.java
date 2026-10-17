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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/** Grava e consulta a tabela Registros (auditoria do sistema). */
public class RegistroRepository {

    private static final DateTimeFormatter FORMATO =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /** Uma linha da tabela Registros ja juntada com o texto da Mensagem. */
    public record Registro(int rid, String dataHora, int mid, String texto,
                           Integer uid, String email, String arquivo) {}

    // Insere um registro. O UID e o arquivo podem ser nulos, pois varios
    // eventos acontecem antes de o usuario ser identificado.
    public void inserir(int mid, Integer uid, String arquivo) throws SQLException {

        String sql = """
            INSERT INTO Registros (MID, UID, ARQUIVO, DATA_HORA)
            VALUES (?, ?, ?, ?)
        """;

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, mid);

            if (uid == null) {
                statement.setNull(2, java.sql.Types.INTEGER);
            } else {
                statement.setInt(2, uid);
            }

            statement.setString(3, arquivo);
            statement.setString(4, LocalDateTime.now().format(FORMATO));

            statement.executeUpdate();
        }
    }

    // Lista todos os registros em ordem cronologica, trazendo o texto da
    // mensagem (tabela Mensagens) e o login do usuario (tabela Usuarios).
    public List<Registro> listarCronologico() throws SQLException {

        String sql = """
            SELECT r.RID, r.DATA_HORA, r.MID, m.TEXTO, r.UID, u.EMAIL, r.ARQUIVO
            FROM Registros r
            JOIN Mensagens m ON m.MID = r.MID
            LEFT JOIN Usuarios u ON u.UID = r.UID
            ORDER BY r.DATA_HORA, r.RID
        """;

        List<Registro> registros = new ArrayList<>();

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {

            while (result.next()) {
                int uid = result.getInt("UID");
                Integer uidOuNulo = result.wasNull() ? null : uid;

                registros.add(new Registro(
                        result.getInt("RID"),
                        result.getString("DATA_HORA"),
                        result.getInt("MID"),
                        result.getString("TEXTO"),
                        uidOuNulo,
                        result.getString("EMAIL"),
                        result.getString("ARQUIVO")));
            }
        }

        return registros;
    }
}
