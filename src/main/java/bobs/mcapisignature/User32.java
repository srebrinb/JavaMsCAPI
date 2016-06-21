/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.mcapisignature;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinDef.HWND;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 *
 * @author sbalabanov
 */
public interface User32 extends Library {
        public User32 INST = (User32) Native.loadLibrary("user32", User32.class);
        HWND GetActiveWindow();
        HWND GetForegroundWindow();
}
