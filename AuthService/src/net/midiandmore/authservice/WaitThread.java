/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package net.midiandmore.authservice;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author windo
 */
public class WaitThread implements Runnable {

    public WaitThread(AuthServ mi) {
        setMi(mi);
        (thread = new Thread(this)).start();
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

    private Thread thread;
    private AuthServ mi;

    @Override
    public void run() {
        while (true) {
            try {
                if (getMi().getSocketThread() == null) {
                    getMi().setSocketThread(new SocketThread(getMi()));
                } else if (getMi().getSocketThread().getSocket() == null) {
                    getMi().getSocketThread().setRuns(false);
                    getMi().setSocketThread(null);
                } else if (getMi().getSocketThread().isRuns()
                        && getMi().getSocketThread().getSocket().isClosed()) {
                    getMi().getSocketThread().setRuns(false);
                    getMi().setSocketThread(null);
                } 
                thread.sleep(15000L);
            } catch (InterruptedException ex) {
                Logger.getLogger(WaitThread.class.getName()).log(Level.SEVERE, null, ex);
                System.exit(1);
            }
        }
    }

}
