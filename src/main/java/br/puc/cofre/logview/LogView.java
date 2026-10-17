/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.logview;

import br.puc.cofre.database.ChaveiroRepository;
import br.puc.cofre.database.DatabaseConnection;
import br.puc.cofre.database.RegistroRepository;
import br.puc.cofre.database.RegistroRepository.Registro;
import br.puc.cofre.database.UsuarioRepository;
import br.puc.cofre.model.Usuario;
import br.puc.cofre.security.CertificadoService;
import br.puc.cofre.security.ChaveService;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

/**
 * Programa de auditoria independente do Cofre Digital.
 * Uso: LogView <caminho do arquivo da chave privada do administrador>
 *
 * Somente o administrador do sistema consegue ver os registros: a frase
 * secreta e lida do teclado sem echo, a chave privada do arquivo e
 * decriptada e validada com a assinatura de 2048 bytes aleatorios contra o
 * certificado do administrador guardado no banco. Se falhar, o programa termina.
 */
public class LogView {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Uso: LogView <caminho-da-chave-privada-do-administrador>");
            System.exit(1);
        }

        try {
            if (!Files.exists(Path.of(DatabaseConnection.caminhoDoBanco()))) {
                System.err.println("Banco de dados " + DatabaseConnection.caminhoDoBanco()
                        + " nao encontrado no diretorio atual.");
                System.exit(1);
            }

            Usuario admin = new UsuarioRepository().buscarAdministradorDoSistema();
            if (admin == null) {
                System.err.println("Nenhum administrador cadastrado no sistema.");
                System.exit(1);
            }

            byte[] chaveCifrada = Files.readAllBytes(Path.of(args[0]));
            String frase = lerFraseSecreta();

            ChaveiroRepository chaveiro = new ChaveiroRepository();
            ChaveService chaves = new ChaveService();
            X509Certificate certificado = new CertificadoService()
                    .carregarDePem(chaveiro.buscarCertificado(admin.getUid()));

            PrivateKey chavePrivada;
            try {
                chavePrivada = chaves.carregarChavePrivada(chaveCifrada, frase);
            } catch (Exception e) {
                System.err.println("Frase secreta invalida ou arquivo de chave incorreto. Encerrando.");
                System.exit(1);
                return;
            }

            if (!chaves.validarParDeChaves(chavePrivada, certificado, 2048)) {
                System.err.println("A chave privada nao corresponde ao certificado do administrador. Encerrando.");
                System.exit(1);
            }

            System.out.println("Administrador " + admin.getEmail() + " autenticado.\n");
            exibirRegistros();

        } catch (Exception e) {
            System.err.println("Falha no logView: " + e.getMessage());
            System.exit(1);
        }
    }

    // Le a frase secreta pelo teclado real, sem exibir os caracteres.
    private static String lerFraseSecreta() {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("Frase secreta da chave privada do administrador: ");
            if (chars == null) {
                throw new IllegalStateException("Entrada encerrada.");
            }
            String frase = new String(chars);
            Arrays.fill(chars, '\0');
            return frase;
        }
        // Sem console (ex.: dentro de uma IDE) nao e possivel desligar o echo.
        System.out.println("AVISO: sem console; a frase secreta sera exibida ao digitar.");
        System.out.print("Frase secreta da chave privada do administrador: ");
        return new Scanner(System.in).nextLine();
    }

    // Exibe data, hora, codigo e a mensagem correspondente, em ordem cronologica.
    private static void exibirRegistros() throws Exception {
        List<Registro> registros = new RegistroRepository().listarCronologico();

        System.out.println("Registros do sistema (" + registros.size() + "):");
        System.out.printf("%-6s %-23s %-5s %s%n", "RID", "DATA E HORA", "MID", "MENSAGEM");

        for (Registro r : registros) {
            String texto = r.texto();
            if (r.email() != null) {
                texto = texto.replace("<login_name>", r.email());
            }
            if (r.arquivo() != null) {
                texto = texto.replace("<arq_name>", r.arquivo());
            }
            System.out.printf("%-6d %-23s %-5d %s%n", r.rid(), r.dataHora(), r.mid(), texto);
        }
    }
}
