package br.org.crypto;

import java.awt.HeadlessException;
import java.io.UnsupportedEncodingException;
import java.math.*;
import java.security.*;
import java.util.Formatter;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static javax.management.Query.lt;
import javax.swing.JOptionPane;
import org.apache.commons.codec.binary.Base64;
import org.jasypt.util.password.*;
import org.jasypt.util.text.*;


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
    
    //SHA
        
           
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
public  String encryptPassword(String password)
{
    String sha1 = "";
    try
    {
        MessageDigest crypt = MessageDigest.getInstance("SHA-1");
        crypt.reset();
        crypt.update(password.getBytes("UTF-8"));
        sha1 = byteToHex(crypt.digest());
    }
    catch(NoSuchAlgorithmException | UnsupportedEncodingException e)
    {
        e.printStackTrace();
    }
    return sha1;
}

public String byteToHex(final byte[] hash)
{
    Formatter formatter = new Formatter();
    for (byte b : hash)
    {
        formatter.format("%02x", b);
    }
    String result = formatter.toString();
    formatter.close();
    return result;
}  
public static String encrypt(String key1, String key2, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(key2.getBytes("UTF-8"));

            SecretKeySpec skeySpec = new SecretKeySpec(key1.getBytes("UTF-8"),
                    "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(value.getBytes());
            System.out.println("encrypted string:"
                    + Base64.encodeBase64String(encrypted));
            return Base64.encodeBase64String(encrypted);
        } catch (UnsupportedEncodingException ex) {
            ex.printStackTrace();
        } catch (InvalidAlgorithmParameterException ex) {
            ex.printStackTrace();
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String key1, String key2, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(key2.getBytes("UTF-8"));

            SecretKeySpec skeySpec = new SecretKeySpec(key1.getBytes("UTF-8"),
                    "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

}
