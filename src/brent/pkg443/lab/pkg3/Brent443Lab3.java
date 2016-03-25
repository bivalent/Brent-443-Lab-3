package brent.pkg443.lab.pkg3;

import java.security.*;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Brent
 */
public class Brent443Lab3 {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /* two files: 'password.txt', 'english.0'
           passwordformat:
        
            adam 0 7d27662bb31cb629178e929287993c01bf7c42ac
            nick 1 a9edd3db 93bbd7dab6e365a5a840584d9849cbd55fbbf469
        */
        BufferedReader br = null;
        String delims = "[ ]+"; // tokens by spaces.
        String[] tokens;
        
        // stores usernames and hashed passwords
        Map<String, String> accountsHash = new HashMap<String, String>();
        Map<String, String> accountsSaltHash = new HashMap<String, String>();
        
        // used for output.
        Map<String, String> accountsPlain = new HashMap<String, String>();
        
        // used to easily generate hashes with salts.
        ArrayList<String> salts = new ArrayList<String>();
        
        //stores the hash and its salt.
        Map<String, String> saltedPasswords = new HashMap<String, String>();
        
        // lookup tables for all generated hashes. one without salts, one with.
        Map<String, String> p2Hash = new HashMap<String, String>();
        Map<String, String> p2HashSalted = new HashMap<String, String>();
        
// ------------------------- 1) Store Passwords -------------------------------
        System.out.println("Storing Passwords from: password.txt\n");
        
        try{
            String sCurrentLine;
            br = new BufferedReader(new FileReader("test/password.txt"));
            
            while((sCurrentLine = br.readLine()) != null)
            {
                tokens = sCurrentLine.split(delims);
                                
                // check if it's salted.
                if(tokens[1].equals("0")) // nope.
                {
                    // store username and hashed password.
                    accountsHash.put(tokens[0], tokens[2]);
                }
                else if(tokens[1].equals("1"))
                {
                    if(tokens[3] != null && tokens[2] != null)
                    {
                        // store username and hashed password.
                        accountsSaltHash.put(tokens[0], tokens[3]);
                        
                        // map: Key=Hash, Value=Its Salt.
                        saltedPasswords.put(tokens[3], tokens[2]);
                        salts.add(tokens[2]);
                    }                        
                    else
                        System.out.println("Error reading file. Got '1' for salted, but missing further params.");
                }
                else
                    System.out.println("Error reading salt paramter. Expecting 0|1.");
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Brent443Lab3.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Brent443Lab3.class.getName()).log(Level.SEVERE, null, ex);
        }
        finally {
            try {
                if(br!=null)
                    br.close();              
            }
            catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        
// ------------------------ 2) CREATE HASH LOOKUP TABLES -----------------------------
        System.out.println("Generating Hashes from Dictionary File.\n");
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        
        try{            
            br = new BufferedReader(new FileReader("test/english.0"));
            String dictWord = "";
            String dictRev = "";
            String noVowels = "";
            String hash = "";
            
            while((dictWord = br.readLine()) != null)
            {
                dictWord = dictWord.trim(); // remove trailing/leading spaces.
                
                // original word hashes             
                byte[] result = mDigest.digest(dictWord.getBytes());
                hash = DatatypeConverter.printHexBinary(result);                      
                p2Hash.put(hash, dictWord);
                
                for(String salt : salts) // "for each salt in the salts arrayL"
                {
                    String saltedP = salt + dictWord;
                    result = mDigest.digest(saltedP.getBytes());
                    hash = DatatypeConverter.printHexBinary(result);
                    p2HashSalted.put(hash, dictWord);
                }
                
               // reversed word hashes
                dictRev = new StringBuilder(dictWord).reverse().toString();
                
                result = mDigest.digest(dictRev.getBytes());
                hash = DatatypeConverter.printHexBinary(result);
                p2Hash.put(hash, dictRev);
                
                for(String salt : salts) // "for each salt in the salts arrayL"
                {
                    String saltedP = salt + dictRev;
                    result = mDigest.digest(saltedP.getBytes());
                    hash = DatatypeConverter.printHexBinary(result);
                    p2HashSalted.put(hash, dictRev);
                }
                
                // no vowel word hashes
                noVowels = dictWord.replaceAll("[AEIOUaeiou]", "");
                
                result = mDigest.digest(noVowels.getBytes());
                hash = DatatypeConverter.printHexBinary(result);
                p2Hash.put(hash, noVowels);
                
                for(String salt : salts) // "for each salt in the salts arrayL"
                {
                    String saltedP = salt + noVowels;
                    result = mDigest.digest(saltedP.getBytes());
                    hash = DatatypeConverter.printHexBinary(result);
                    p2HashSalted.put(hash, noVowels);
                }
                
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Brent443Lab3.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Brent443Lab3.class.getName()).log(Level.SEVERE, null, ex);
        }
        finally {
            try {
                if(br!=null)
                    br.close();              
            }
            catch (IOException ex) {
                ex.printStackTrace();
            }
        }
     
// ------------------------ 3) Compare Hashes, find passwords.- ----------------------------
        /* VARIABLE REFERENCES (So I don't have to scroll)
        
            // stores usernames and hashed passwords
            Map accountsHash
            Map accountsSaltHash
            // used to easily generate hashes with salts.
            ArrayList salts

            //stores the hash and its salt.
            Map saltedPasswords

            // lookup tables for all generated hashes. one without salts, one with.
            Map p2Hash
            Map P2HashSalted
        */
        
        //iterate through accountsHash (non salted passwords). Write text file of username-passwords
        System.out.println("First, cracking non-salted passwords.\n");
        String username = "";
        String hashPass = "";
        String plainPass = "";
        
        for (Map.Entry<String, String> entry : accountsHash.entrySet())
        {
            username = entry.getKey();
            hashPass = entry.getValue();
            
            if(p2Hash.containsKey(hashPass)) // found a match.
            {
                plainPass = p2Hash.get(hashPass);
                accountsPlain.put(username, plainPass);
            }
            else
                System.out.println("Hash not found. User: " + username + "\nPassword: " + hashPass + ".\n");
        }
        System.out.println("Now cracking salted passwords.\n");
        // iterate through salted passwords.
        for (Map.Entry<String, String> entry : accountsSaltHash.entrySet())
        {
            username = entry.getKey();
            hashPass = entry.getValue(); 
            
            
            if(p2HashSalted.containsKey(hashPass))
            {
                plainPass = p2Hash.get(hashPass);
                accountsPlain.put(username, plainPass);
            }
            else
                System.out.println("Hash not found. User: " + username + "\nPassword: " + hashPass + ".\n");
        }
        
// ---------- 4) Output Username/Password (plaintext) Combinations -------------
        System.out.println("Users and their passwords: \n");
        
        try 
        {           
            PrintWriter writer = new PrintWriter("passwordOutput.txt", "UTF-8");
            
            for (Map.Entry<String, String> entry : accountsPlain.entrySet())
            {
                username = entry.getKey();
                plainPass = entry.getValue();
                
                System.out.println(username + "\t" + plainPass);
                writer.println(username + "\t" + plainPass);
            }          
          
            writer.close();
        } catch (FileNotFoundException ex)
        {
            Logger.getLogger(Brent443Lab3.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex)
        {
            Logger.getLogger(Brent443Lab3.class.getName()).log(Level.SEVERE, null, ex);
        }      
        
    }    
}
