/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.database;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/** Cria as cinco tabelas do cofre (Grupos, Usuarios, Chaveiro, Mensagens, Registros). */
public class DatabaseInitializer {

    public static void initialize() throws SQLException {

        try (Connection connection = DatabaseConnection.getConnection();
             Statement statement = connection.createStatement()) {

            statement.execute("PRAGMA foreign_keys = ON");

            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS Grupos (
                    GID INTEGER PRIMARY KEY,
                    NOME TEXT NOT NULL UNIQUE
                )
            """);

            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS Usuarios (
                    UID INTEGER PRIMARY KEY AUTOINCREMENT,
                    EMAIL TEXT NOT NULL UNIQUE,
                    NOME TEXT NOT NULL,
                    GID INTEGER NOT NULL,
                    KID INTEGER UNIQUE,
                    SENHA_HASH TEXT NOT NULL,
                    TOKEN_KEY TEXT NOT NULL,
                    TOTAL_ACESSOS INTEGER NOT NULL DEFAULT 0,
                    TOTAL_CONSULTAS INTEGER NOT NULL DEFAULT 0,
                    TENTATIVAS_SENHA INTEGER NOT NULL DEFAULT 0,
                    TENTATIVAS_TOKEN INTEGER NOT NULL DEFAULT 0,
                    BLOQUEADO_ATE INTEGER,
                    FOREIGN KEY (GID) REFERENCES Grupos(GID)
                )
            """);

            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS Chaveiro (
                    KID INTEGER PRIMARY KEY AUTOINCREMENT,
                    UID INTEGER NOT NULL UNIQUE,
                    CHAVE_PRIVADA BLOB NOT NULL,
                    CERTIFICADO TEXT NOT NULL,
                    FOREIGN KEY (UID) REFERENCES Usuarios(UID)
                )
            """);

            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS Mensagens (
                    MID INTEGER PRIMARY KEY,
                    TEXTO TEXT NOT NULL
                )
            """);

            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS Registros (
                    RID INTEGER PRIMARY KEY AUTOINCREMENT,
                    MID INTEGER NOT NULL,
                    UID INTEGER,
                    ARQUIVO TEXT,
                    DATA_HORA TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (MID) REFERENCES Mensagens(MID),
                    FOREIGN KEY (UID) REFERENCES Usuarios(UID)
                )
            """);

            // Grupos padrao do sistema
            statement.executeUpdate("""
                INSERT OR IGNORE INTO Grupos (GID, NOME)
                VALUES (1, 'Administrador'), (2, 'Usuario')
            """);
        }
    }
}
