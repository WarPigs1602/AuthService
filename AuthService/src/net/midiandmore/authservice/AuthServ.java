/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package net.midiandmore.authservice;

/**
 *
 * @author Andreas Pschorn
 */
public class AuthServ implements Software {

    /**
     * @return the waitThread
     */
    public WaitThread getWaitThread() {
        return waitThread;
    }

    /**
     * @param waitThread the waitThread to set
     */
    public void setWaitThread(WaitThread waitThread) {
        this.waitThread = waitThread;
    }

    /**
     * @return the socketThread
     */
    public SocketThread getSocketThread() {
        return socketThread;
    }

    /**
     * @param socketThread the socketThread to set
     */
    public void setSocketThread(SocketThread socketThread) {
        this.socketThread = socketThread;
    }

    /**
     * @return the config
     */
    public Config getConfig() {
        return config;
    }

    /**
     * @param config the config to set
     */
    public void setConfig(Config config) {
        this.config = config;
    }

    private Config config;
    private SocketThread socketThread;
    private WaitThread waitThread;
    private Database db;
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            new AuthServ(args);
        } catch (Exception e) {
        }
    }

    protected AuthServ(String[] args) {
        init(args);
    }

    protected void init(String[] args) {
        System.out.println("HostServ " + VERSION);
        System.out.println("By " + AUTHOR);
        System.out.println();
        setConfig(new Config(this, "config-authserv.json"));
        setDb(new Database(this));
        setWaitThread(new WaitThread(this));
    }

    /**
     * @return the db
     */
    public Database getDb() {
        return db;
    }

    /**
     * @param db the db to set
     */
    public void setDb(Database db) {
        this.db = db;
    }
}
