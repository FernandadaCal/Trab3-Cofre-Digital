/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.view;

import br.puc.cofre.model.ArquivoProtegido;
import br.puc.cofre.model.Usuario;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;

/**
 * Tela de Consulta da pasta de arquivos secretos: formulario (pasta e frase),
 * botao Listar, tabela com os arquivos autorizados e recuperacao do arquivo
 * selecionado. As regras ficam no CofreDigitalService, acessado pelas Acoes.
 */
public class TelaConsulta extends JDialog {

    /** O que a tela pede ao servico quando um botao e pressionado. */
    public interface Acoes {
        // Valida pasta e frase, le os indices e devolve os arquivos que o usuario pode ver.
        List<ArquivoProtegido> listar(String caminhoPasta, String frase) throws Exception;

        String origemAcesso(ArquivoProtegido arquivo);

        // Decripta e verifica o arquivo; devolve a mensagem de sucesso para a tela.
        String recuperar(ArquivoProtegido arquivo) throws Exception;

        int totalConsultas();

        void voltar();
    }

    private static final String[] COLUNAS = {"Nome secreto", "Dono", "Grupo", "Acesso"};

    private final Acoes acoes;
    private final JLabel total = new JLabel();
    private final JTextField caminhoPasta = new JTextField(40);
    private final JPasswordField frase = new JPasswordField(40);
    private final DefaultTableModel modelo = new DefaultTableModel(COLUNAS, 0) {
        @Override
        public boolean isCellEditable(int linha, int coluna) {
            return false;
        }
    };
    private final JTable tabela = new JTable(modelo);
    private final JButton recuperar = new JButton("Decriptar arquivo selecionado");

    // Arquivos da ultima listagem, na mesma ordem das linhas da tabela.
    private List<ArquivoProtegido> listados = new ArrayList<>();

    private TelaConsulta(Usuario usuario, Acoes acoes) {
        super((Frame) null, "Cofre Digital - Consultar pasta de arquivos secretos", true);
        this.acoes = acoes;
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel cabecalho = Componentes.cabecalho(usuario, null);
        cabecalho.add(total);
        atualizarTotal();

        JPanel formulario = Componentes.formulario();
        Componentes.linha(formulario, "Caminho da pasta:", caminhoPasta);
        Componentes.linha(formulario, "Frase secreta:", frase);
        JButton listar = new JButton("Listar");
        listar.addActionListener(e -> listar());
        formulario.add(new JLabel());
        formulario.add(listar);

        tabela.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane rolagem = new JScrollPane(tabela);
        rolagem.setPreferredSize(new Dimension(700, 180));

        recuperar.setEnabled(false);
        recuperar.addActionListener(e -> recuperar());
        JButton voltar = new JButton("Voltar para o Menu Principal");
        voltar.addActionListener(e -> voltar());
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                voltar();
            }
        });

        JPanel topo = new JPanel(new BorderLayout());
        topo.add(cabecalho, BorderLayout.NORTH);
        topo.add(formulario, BorderLayout.CENTER);
        JPanel botoes = new JPanel();
        botoes.add(recuperar);
        botoes.add(voltar);
        getRootPane().setDefaultButton(listar);
        add(topo, BorderLayout.NORTH);
        add(rolagem, BorderLayout.CENTER);
        add(botoes, BorderLayout.SOUTH);
        pack();
        setLocationRelativeTo(null);
    }

    public static void mostrar(Usuario usuario, Acoes acoes) {
        new TelaConsulta(usuario, acoes).setVisible(true);
    }

    private void listar() {
        String fraseDigitada = new String(frase.getPassword());
        frase.setText("");
        modelo.setRowCount(0);
        listados = new ArrayList<>();
        recuperar.setEnabled(false);
        try {
            listados = acoes.listar(caminhoPasta.getText().trim(), fraseDigitada);
            for (ArquivoProtegido a : listados) {
                modelo.addRow(new Object[] {a.nomeSecreto(), a.dono(), a.grupo(), acoes.origemAcesso(a)});
            }
            recuperar.setEnabled(!listados.isEmpty());
            if (listados.isEmpty()) {
                Componentes.mostrarInfo("Consulta", "Nenhum arquivo autorizado nesta pasta.");
            }
        } catch (Exception e) {
            Componentes.mostrarErro("Consulta", e.getMessage());
        }
        atualizarTotal();
    }

    private void recuperar() {
        int linha = tabela.getSelectedRow();
        if (linha < 0 || linha >= listados.size()) {
            Componentes.mostrarErro("Consulta", "Selecione um arquivo da lista.");
            return;
        }
        ArquivoProtegido arquivo = listados.get(linha);
        try {
            Componentes.mostrarInfo("Arquivo recuperado", acoes.recuperar(arquivo));
        } catch (Exception e) {
            Componentes.mostrarErro("Falha ao recuperar " + arquivo.nomeSecreto(), e.getMessage());
        }
    }

    private void voltar() {
        acoes.voltar();
        dispose();
    }

    private void atualizarTotal() {
        total.setText("Total de consultas do usuario: " + acoes.totalConsultas());
    }
}
