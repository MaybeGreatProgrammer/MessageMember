package com.luszczyk;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

class Client {
    private Socket clientSocket;
    private PrintWriter out;
    private Scanner reader;
    private BufferedReader in;
    private KeyPair originalKeyPair;
    private SecretKey secretKey;

    void start(String ip) throws IOException, GeneralSecurityException {
        clientSocket = new Socket(ip, 8888);
        originalKeyPair = MSGEncrypt.generateKeyPair();
        out = new PrintWriter(clientSocket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String initLine;

        try {
            //Asks for keys encrypted with own public key
            out.println("!requestaes " + MSGEncrypt.keyToString(originalKeyPair.getPublic()));
            while (true) {
                initLine = in.readLine();
                if (initLine.startsWith("!aes")){
                    secretKey = MSGEncrypt.loadSecretKey(MSGEncrypt.decrypt(initLine.replace("!aes ", ""), originalKeyPair.getPrivate()));
                    break;
                }
                if (initLine.startsWith("!password")){
                    System.out.print("Enter password: ");
                    byte[] key = new Scanner(System.in).next().getBytes();
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key, 16); // use only first 128 bit
                    secretKey = new SecretKeySpec(key, "AES");
                    out.println(MSGEncrypt.AESEncrypt("!ok",secretKey));
                    break;
                }
            }
        }catch(Exception e){
            e.printStackTrace();
        }
        new Reciever().start();
        String userInput;
        reader = new Scanner(System.in);
        while(true) {
            userInput = reader.nextLine();
            out.println(MSGEncrypt.AESEncrypt(userInput, secretKey));
        }
    }

    private class Reciever extends Thread{

        Reciever() {
        }

        public void run(){
            try {
                String inputLine = null;
                while (true) {
                    try {
                        inputLine = in.readLine();
                    } catch (Exception e){
                        System.out.println("The server has shut down");
                        System.exit(2);
                    }
                    if (inputLine != null) {
                        if(inputLine.equals("!badpass")) {
                            System.out.println("Bad password");
                            System.exit(3);
                        }
                        inputLine = MSGEncrypt.AESDecrypt(inputLine, secretKey);
                        System.out.println(inputLine);
                    }
                }
            } catch(Exception e) {
                e.printStackTrace();
            }
        }

    }
}
