/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.mcapisignature;

import com.sun.jna.Native;

/**
 *
 * @author sbalabanov
 */
public class MCAPIException extends Exception {

    public MCAPIException(String message) {
        super(message+" (0x"+Integer.toHexString(Native.getLastError())+")");
    }
    
}
