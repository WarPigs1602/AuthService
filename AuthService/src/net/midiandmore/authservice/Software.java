/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package net.midiandmore.authservice;

/**
 *
 * @author Andreas Pschorn
 */
public interface Software {

    String VERSION = "1.0";
    String VENDOR = "MidiAndMore.Net";
    String AUTHOR = "Andreas Pschorn (WarPigs)";
    int QUFLAG_INACTIVE = 0x0001;
    /* +I */
    int QUFLAG_GLINE = 0x0002;
    /* +g */
    int QUFLAG_NOTICE = 0x0004;
    /* +n */
    int QUFLAG_STAFF = 0x0008;
    /* +q */
    int QUFLAG_SUSPENDED = 0x0010;
    /* +z */
    int QUFLAG_OPER = 0x0020;
    /* +o */
    int QUFLAG_DEV = 0x0040;
    /* +d */
    int QUFLAG_PROTECT = 0x0080;
    /* +p */
    int QUFLAG_HELPER = 0x0100;
    /* +h */
    int QUFLAG_ADMIN = 0x0200;
    /* +a */
    int QUFLAG_INFO = 0x0400;
    /* +i */
    int QUFLAG_DELAYEDGLINE = 0x0800;
    /* +G */
    int QUFLAG_NOAUTHLIMIT = 0x1000;
    /* +L */
    int QUFLAG_ACHIEVEMENTS = 0x2000;
    /* +c */
    int QUFLAG_CLEANUPEXEMPT = 0x4000;
    /* +D */
    int QUFLAG_TRUST = 0x8000;
    /* +T */
    int QUFLAG_ALL = 0xffff;
}
