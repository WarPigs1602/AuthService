/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package net.midiandmore.authservice;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author The database class
 */
public class Database {

    private AuthServ mi;
    private boolean connected;
    private Connection conn;

    protected Database(AuthServ mi) {
        setMi(mi);
        setConnected(false);
        connect();
    }

    private void connect() {
        var config = getMi().getConfig().getConfigFile();
        var url = "jdbc:postgresql://%s/%s".formatted(config.get("dbhost"), config.get("db"));
        var props = new Properties();
        props.setProperty("user", (String) config.get("dbuser"));
        props.setProperty("password", (String) config.get("dbpassword"));
        props.setProperty("ssl", (String) config.get("dbssl"));
        try {
            System.out.println("Connecting to database...");
            setConn(DriverManager.getConnection(url, props));
            setConnected(true);
            System.out.println("Successfully connected to databse...");
        } catch (SQLException ex) {
            System.out.println("Connection to database failed: " +ex.getMessage());
            setConnected(false);
        }
    }

    /**
     * Fetching flags
     *
     * @return The data
     */
    protected int getFlags(String nick) {
        var dat = 0;
        try (var statement = getConn().prepareStatement("SELECT flags FROM chanserv.users WHERE username = ?;")) {
            statement.setString(1, nick);
            try (var resultset = statement.executeQuery()) {
                while (resultset.next()) {
                    dat = resultset.getInt("flags");
                }
            }
        } catch (SQLException ex) {
            System.out.println("Access to database failed: " + ex.getMessage());
        }
        return dat;
    }
    
    /**
     * Fetching flags
     *
     * @return The data
     */
    protected HashMap<String, Integer> getFlags() {
        var dat = new HashMap<String, Integer>();
        try (var statement = getConn().prepareStatement("SELECT flags, username FROM chanserv.users WHERE flags > 4;")) {
            try (var resultset = statement.executeQuery()) {
                while (resultset.next()) {
                    dat.put(resultset.getString("username"), resultset.getInt("flags"));
                }
            }
        } catch (SQLException ex) {
            System.out.println("Access to database failed: " + ex.getMessage());
        }
        return dat;
    }    

    /**
     * Is registered
     *
     * @return The data
     */
    protected String getTimestamp(String nick) {
        String dat = null;
        try (var statement = getConn().prepareStatement("SELECT lastauth FROM chanserv.users WHERE username = ?;")) {
            statement.setString(1, nick);
            try (var resultset = statement.executeQuery()) {
                while (resultset.next()) {
                   dat = resultset.getString("lastauth");
                }
            }
        } catch (SQLException ex) {
            System.out.println("Access to database failed: " + ex.getMessage());
        }
        return dat;
    }
    
    /**
     * Is registered
     *
     * @return The data
     */
    protected String getId(String nick) {
        String dat = null;
        try (var statement = getConn().prepareStatement("SELECT id FROM chanserv.users WHERE username = ?;")) {
            statement.setString(1, nick);
            try (var resultset = statement.executeQuery()) {
                while (resultset.next()) {
                   dat = resultset.getString("id");
                }
            }
        } catch (SQLException ex) {
            System.out.println("Access to database failed: " + ex.getMessage());
        }
        return dat;
    }
    
    /**
     * Is registered
     *
     * @return The data
     */
    protected boolean isRegistered(String nick, String password) {
        var dat = false;
        try (var statement = getConn().prepareStatement("SELECT * FROM chanserv.users WHERE username = ? AND password = ?;")) {
            statement.setString(1, nick);
            statement.setString(2, password);
            try (var resultset = statement.executeQuery()) {
                while (resultset.next()) {
                   if (!resultset.getString("password").isBlank()) {
                       dat = true;
                   }
                }
            }
        } catch (SQLException ex) {
            System.out.println("Access to database failed: " + ex.getMessage());
        }
        return dat;
    }
    
    /**
     * Commits
     */
    protected void commit() {
        try {
            try (var statement = getConn().prepareStatement("COMMIT")) {
                statement.executeUpdate();
            }
        } catch (SQLException ex) {
            System.out.println("Access to database failed: " + ex.getMessage());
        }
    }
    
    /**
     * Begins a transaction
     */
    protected void transcation() {
        try {
            try (var statement = getConn().prepareStatement("BEGIN TRANSACTION")) {
                statement.executeUpdate();
            }
        } catch (SQLException ex) {
            System.out.println("Access to database failed: " + ex.getMessage());
        }
    }

    /**
     * @return the mi
     */
    public AuthServ getMi() {
        return mi;
    }

    /**
     * @param mi the mi to set
     */
    public void setMi(AuthServ mi) {
        this.mi = mi;
    }

    /**
     * @return the connected
     */
    public boolean isConnected() {
        return connected;
    }

    /**
     * @param connected the connected to set
     */
    public void setConnected(boolean connected) {
        this.connected = connected;
    }

    /**
     * @return the conn
     */
    public Connection getConn() {
        return conn;
    }

    /**
     * @param conn the conn to set
     */
    public void setConn(Connection conn) {
        this.conn = conn;
    }
}
