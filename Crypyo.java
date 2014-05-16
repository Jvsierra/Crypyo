package br.org.crypto;

import java.awt.HeadlessException;
import java.io.UnsupportedEncodingException;
import org.jasypt.util.password.*;
import org.jasypt.util.text.*;
import java.security.*;
import java.math.*;
import javax.swing.JOptionPane;

public class Crypyo {
    //jasypt
    private String txt;
    private String password;
    private String encTxt;
    private String encPass;
    private int num;
    private int encNum;
    private String unectxt;
    
    public void enc_jasypt_string(String txt){
            BasicTextEncryptor bte = new BasicTextEncryptor();
            bte.setPassword(password);
            JOptionPane.showInputDialog("Jasypt", bte.encrypt(txt));
            
    }
    public void jasypt_pass(){
        StrongPasswordEncryptor spe = new StrongPasswordEncryptor();
        encPass = spe.encryptPassword(password);
       JOptionPane.showMessageDialog(null, "Enc string: "+encPass);
    }
    public void jasypt_txt(){
       StrongTextEncryptor ste = new StrongTextEncryptor();
       ste.setPassword(txt);
      ste.encrypt(txt);
      encTxt =ste.encrypt(txt);
       JOptionPane.showMessageDialog(null, "Enc string: "+encTxt);
    }
    public void jasypt_unenc(String txt){
        try{
            BasicTextEncryptor bte = new BasicTextEncryptor();
            bte.setPassword(password);
            String unectxt = bte.decrypt(txt);
            JOptionPane.showInputDialog("Jasypt", unectxt);
        }catch(HeadlessException ex){
            JOptionPane.showMessageDialog(null, "Error: "+ex);
        }
    }
  
    public String getTxt() {
        return txt;
    }
    public void setTxt(String txt) {
        this.txt = txt;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    //MD5
    public void encrypt_MD5(String enc) throws NoSuchAlgorithmException{
        MessageDigest m=MessageDigest.getInstance("MD5");
         m.update(enc.getBytes(),0,enc.length());
          JOptionPane.showInputDialog(null, "MD5", new BigInteger(1,m.digest()).toString(16));
                  }
    
    //SHA - SHA - 256
        
           
        public String sha256(String base) {
    try{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(base.getBytes("UTF-8"));
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    } catch(UnsupportedEncodingException ex){
       throw new RuntimeException(ex);
    }   catch (NoSuchAlgorithmException ex) {
        throw new RuntimeException(ex);
        }
}
    
}
