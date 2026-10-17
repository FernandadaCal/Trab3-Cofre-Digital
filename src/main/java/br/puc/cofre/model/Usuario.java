/*
 * INF1416 - Seguranca da Informacao - Trabalho 3 - Cofre Digital
 * Integrante 1:  Fernanda Figueiredo - Matricula: 2312090
 * Integrante 2: Pedro Vanini - Matricula: 2310605
 */
package br.puc.cofre.model;

/** Linha da tabela Usuarios, incluindo contadores e estado de bloqueio. */
public class Usuario {

    private int uid;
    private String email;
    private String nome;
    private int gid;
    private Integer kid;

    private String senhaHash;
    private String tokenKey;

    private int totalAcessos;
    private int totalConsultas;

    private int tentativasSenha;
    private int tentativasToken;

    private Long bloqueadoAte;

    public Usuario() {
    }

    public Usuario(String email, String nome, int gid,
                   String senhaHash, String tokenKey) {

        this.email = email;
        this.nome = nome;
        this.gid = gid;
        this.senhaHash = senhaHash;
        this.tokenKey = tokenKey;

        this.totalAcessos = 0;
        this.totalConsultas = 0;
        this.tentativasSenha = 0;
        this.tentativasToken = 0;
    }

    public int getUid() {
        return uid;
    }

    public void setUid(int uid) {
        this.uid = uid;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public int getGid() {
        return gid;
    }

    public void setGid(int gid) {
        this.gid = gid;
    }

    public Integer getKid() {
        return kid;
    }

    public void setKid(Integer kid) {
        this.kid = kid;
    }

    public String getSenhaHash() {
        return senhaHash;
    }

    public void setSenhaHash(String senhaHash) {
        this.senhaHash = senhaHash;
    }

    public String getTokenKey() {
        return tokenKey;
    }

    public void setTokenKey(String tokenKey) {
        this.tokenKey = tokenKey;
    }

    public int getTotalAcessos() {
        return totalAcessos;
    }

    public void setTotalAcessos(int totalAcessos) {
        this.totalAcessos = totalAcessos;
    }

    public int getTotalConsultas() {
        return totalConsultas;
    }

    public void setTotalConsultas(int totalConsultas) {
        this.totalConsultas = totalConsultas;
    }

    public int getTentativasSenha() {
        return tentativasSenha;
    }

    public void setTentativasSenha(int tentativasSenha) {
        this.tentativasSenha = tentativasSenha;
    }

    public int getTentativasToken() {
        return tentativasToken;
    }

    public void setTentativasToken(int tentativasToken) {
        this.tentativasToken = tentativasToken;
    }

    // Nome do grupo conforme a tabela Grupos (1 = Administrador, 2 = Usuario).
    public static String nomeDoGrupo(int gid) {
        return gid == 1 ? "Administrador" : "Usuario";
    }

    public String getNomeGrupo() {
        return nomeDoGrupo(gid);
    }

    public Long getBloqueadoAte() {
        return bloqueadoAte;
    }

    public void setBloqueadoAte(Long bloqueadoAte) {
        this.bloqueadoAte = bloqueadoAte;
    }
}
