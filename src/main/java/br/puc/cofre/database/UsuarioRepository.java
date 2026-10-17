/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.database;

import br.puc.cofre.model.Usuario;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Acesso a tabela Usuarios. */
public class UsuarioRepository {

    public Usuario buscarPorEmail(String email) throws SQLException {

        String sql = "SELECT * FROM Usuarios WHERE EMAIL = ?";

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, email);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    return mapearUsuario(result);
                }
            }
        }

        return null;
    }

    public Usuario buscarPorId(int uid) throws SQLException {

        String sql = "SELECT * FROM Usuarios WHERE UID = ?";

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, uid);

            try (ResultSet result = statement.executeQuery()) {
                if (result.next()) {
                    return mapearUsuario(result);
                }
            }
        }

        return null;
    }

    public boolean existeAdministrador() throws SQLException {

        String sql = """
            SELECT COUNT(*)
            FROM Usuarios
            WHERE GID = 1
        """;

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {

            return result.next() && result.getInt(1) > 0;
        }
    }

    // O administrador do sistema (dono da pasta segura) e o primeiro
    // administrador cadastrado, ou seja, o de menor UID no grupo 1.
    public Usuario buscarAdministradorDoSistema() throws SQLException {

        String sql = """
            SELECT *
            FROM Usuarios
            WHERE GID = 1
            ORDER BY UID
            LIMIT 1
        """;

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {

            if (result.next()) {
                return mapearUsuario(result);
            }
        }

        return null;
    }

    // Total mostrado na Tela de Cadastro.
    public int contarUsuarios() throws SQLException {

        String sql = "SELECT COUNT(*) FROM Usuarios";

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {

            return result.next() ? result.getInt(1) : 0;
        }
    }

    // Deve ser chamado dentro de uma transacao de cadastro.
    public int inserir(Usuario usuario, Connection connection)
            throws SQLException {

        String sql = """
            INSERT INTO Usuarios
                (EMAIL, NOME, GID, SENHA_HASH, TOKEN_KEY)
            VALUES (?, ?, ?, ?, ?)
        """;

        try (PreparedStatement statement = connection.prepareStatement(
                sql, Statement.RETURN_GENERATED_KEYS)) {

            statement.setString(1, usuario.getEmail());
            statement.setString(2, usuario.getNome());
            statement.setInt(3, usuario.getGid());
            statement.setString(4, usuario.getSenhaHash());
            statement.setString(5, usuario.getTokenKey());

            statement.executeUpdate();

            try (ResultSet keys = statement.getGeneratedKeys()) {

                if (keys.next()) {
                    int uid = keys.getInt(1);
                    usuario.setUid(uid);
                    return uid;
                }
            }
        }

        throw new SQLException("Nao foi possivel obter o UID do usuario.");
    }

    public void atualizarKid(int uid, int kid, Connection connection)
            throws SQLException {

        String sql = "UPDATE Usuarios SET KID = ? WHERE UID = ?";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, kid);
            statement.setInt(2, uid);

            int linhas = statement.executeUpdate();

            if (linhas != 1) {
                throw new SQLException("Usuario nao encontrado para atualizar KID.");
            }
        }
    }

    // Atualiza os contadores e o bloqueio do usuario.
    public void atualizarEstadoAutenticacao(Usuario usuario)
            throws SQLException {

        String sql = """
            UPDATE Usuarios
            SET TOTAL_ACESSOS = ?,
                TOTAL_CONSULTAS = ?,
                TENTATIVAS_SENHA = ?,
                TENTATIVAS_TOKEN = ?,
                BLOQUEADO_ATE = ?
            WHERE UID = ?
        """;

        try (Connection connection = DatabaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, usuario.getTotalAcessos());
            statement.setInt(2, usuario.getTotalConsultas());
            statement.setInt(3, usuario.getTentativasSenha());
            statement.setInt(4, usuario.getTentativasToken());

            if (usuario.getBloqueadoAte() == null) {
                statement.setNull(5, java.sql.Types.BIGINT);
            } else {
                statement.setLong(5, usuario.getBloqueadoAte());
            }

            statement.setInt(6, usuario.getUid());
            statement.executeUpdate();
        }
    }

    private Usuario mapearUsuario(ResultSet result) throws SQLException {

        Usuario usuario = new Usuario();

        usuario.setUid(result.getInt("UID"));
        usuario.setEmail(result.getString("EMAIL"));
        usuario.setNome(result.getString("NOME"));
        usuario.setGid(result.getInt("GID"));

        int kid = result.getInt("KID");
        usuario.setKid(result.wasNull() ? null : kid);

        usuario.setSenhaHash(result.getString("SENHA_HASH"));
        usuario.setTokenKey(result.getString("TOKEN_KEY"));

        usuario.setTotalAcessos(result.getInt("TOTAL_ACESSOS"));
        usuario.setTotalConsultas(result.getInt("TOTAL_CONSULTAS"));

        usuario.setTentativasSenha(result.getInt("TENTATIVAS_SENHA"));
        usuario.setTentativasToken(result.getInt("TENTATIVAS_TOKEN"));

        long bloqueadoAte = result.getLong("BLOQUEADO_ATE");
        usuario.setBloqueadoAte(
            result.wasNull() ? null : bloqueadoAte
        );

        return usuario;
    }
}
