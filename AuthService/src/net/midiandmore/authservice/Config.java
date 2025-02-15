/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package net.midiandmore.authservice;

import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Properties;

/**
 * Loads the iAuthd config
 *
 * @author Andreas Pschorn
 */
public class Config {

    private AuthServ mi;
    private Properties configFile;
    
    /**
     * Initiales the class
     *
     * @param mi The AuthServ class
     * @param configFile
     */
    protected Config(AuthServ mi, String configFile) {
        System.out.println("Loading config...");                
        setMi(mi);
        loadConfig(configFile);
        System.out.println("Config loaded...");       
    }

    /**
     * Loads the config files in the Properties
     */
    private void loadConfig(String configFile) {
        setConfigFile(loadDataFromJSONasProperties(configFile, "name", "value"));
    }

    /**
     * Loads the config data from a JSON file
     *
     * @param file The file
     * @param obj First element
     * @param obj2 Second element
     * @return The properties
     */
    protected Properties loadDataFromJSONasProperties(String file, String obj, String obj2) {
        createFileIfNotExists(file);
        var ar = new Properties();
        try {
            InputStream is = new FileInputStream(file);
            var rdr = Json.createReader(is);
            var results = rdr.readArray();
            var i = 0;
            for (var jsonValue : results) {
                var jobj = results.getJsonObject(i);
                ar.put(jobj.getString(obj), jobj.getString(obj2));
                i++;
            }
        } catch (Exception fne) {
            fne.printStackTrace();
        }
        return ar;
    }

    protected void createFileIfNotExists(String file) {
        File f = new File(file);
        if (!f.exists()) {
            try {
                f.createNewFile();
                FileWriter is = new FileWriter(file);
                PrintWriter pw = new PrintWriter(is);
                pw.println("[");
                pw.println("]");
                is.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    protected void saveDataToJSON(String file, Properties ar, String name, String value) {
        createFileIfNotExists(file);
        FileWriter is = null;
        try {
            is = new FileWriter(file);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        PrintWriter pw = new PrintWriter(is);
        int i = 0;
        pw.println("[");
        for (var jsonValue : ar.keySet()) {
            JsonObjectBuilder obj = Json.createObjectBuilder();
            obj.add(name, (String) jsonValue);
            obj.add(value, ar.getProperty((String) jsonValue));
            pw.print(obj.build().toString());
            i++;
            if (ar.size() != i) {
                pw.println(",");
            } else {
                pw.println("");
            }
        }
        pw.println("]");
        try {
            is.close();
        } catch (IOException ex) {
            ex.printStackTrace();
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
     * @return the configFile
     */
    public Properties getConfigFile() {
        return configFile;
    }

    /**
     * @param configFile the configFile to set
     */
    public void setConfigFile(Properties configFile) {
        this.configFile = configFile;
    }
}
