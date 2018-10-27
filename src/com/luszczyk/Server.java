package com.luszczyk;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class Server {
    private ServerSocket serverSocket;
    private ArrayList<Member> clientList = new ArrayList<>();
    private Integer clientNumber = 0;
    private SecretKey secretKey;
    private static Integer M_ENCRYPTED = 0;
    private static Integer M_CDE = 1;
    private static Integer M_PASSWORD = 2;
    private Integer mode;

    void start(Integer server_mode) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        mode = server_mode;
        serverSocket = new ServerSocket(8888);
        if(mode==M_PASSWORD){
            System.out.print("Enter password: ");
            byte[] key = new Scanner(System.in).next().getBytes();
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // use only first 128 bit
            secretKey = new SecretKeySpec(key, "AES");
        } else if (mode==M_ENCRYPTED){
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128); // The AES key size in number of bits
            secretKey = generator.generateKey();
        }

        System.out.println("Server started");
        while (true){
            Socket clientSocket = serverSocket.accept();
            Member client = new Member();
            client.setName(clientNumber.toString());
            client.setSocket(clientSocket);
            client.setWriter(new PrintWriter(clientSocket.getOutputStream(), true));
            if(mode==M_CDE) {
                KeyGenerator generator = KeyGenerator.getInstance("AES");
                generator.init(128); // The AES key size in number of bits
                client.setSecretKey(generator.generateKey());
            }
            clientNumber += 1;
            clientList.add(client);
            new ClientHandler(client).start();
        }
    }

    public void stop() throws IOException {
        serverSocket.close();
    }

    private class ClientHandler extends Thread {
        private Member client;
        private Socket clientSocket;
        private BufferedReader in;
        private PublicKey oldPuc;
        private Boolean init = true;
        private SecretKey secKey;
        private volatile Boolean running = true;

        ClientHandler(Member client) {
            this.client = client;
            this.clientSocket = client.getSocket();
        }

        public void run() {
            try{
                if(mode==M_CDE) secKey = client.getSecretKey();
                else secKey = secretKey;
                in = new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream()));
                String inputLine;
                while (running) {
                    try {
                        inputLine = in.readLine();
                    } catch (Exception e){
                        client.getSocket().close();
                        clientList.remove(client);
                        running = false;
                        broadcast(client.getName() + " has disconnected", false, false);
                        break;
                    }
                    if(inputLine != null) {
                        String inputLineX;
                        try {
                            inputLineX = MSGEncrypt.AESDecrypt(inputLine, secKey);
                        } catch(Exception e){
                            inputLineX = inputLine;
                        }
                        inputLine = inputLineX;
                        if(inputLine.startsWith("!")) {
                            if(inputLine.startsWith("!requestaes")&&init) {
                                if(mode==M_PASSWORD){
                                    client.getWriter().println("!password");
                                    while(true) {
                                        try{
                                            inputLine = in.readLine();
                                        } catch(Exception e){
                                            client.getSocket().close();
                                            clientList.remove(client);
                                            running = false;
                                            break;
                                        }
                                        try {
                                            inputLineX = MSGEncrypt.AESDecrypt(inputLine, secKey);
                                        } catch(Exception e){
                                            inputLineX = inputLine;
                                        }
                                        if(inputLineX.equals("!ok")) break;
                                        else{
                                            client.getWriter().println("!badpass");
                                            client.getSocket().close();
                                            running = false;
                                            break;
                                        }
                                    }
                                } else {
                                    String oldPS = inputLine.replace("!requestaes ", "");
                                    oldPuc = MSGEncrypt.loadPublicKey(oldPS);
                                    client.getWriter().println("!aes " + MSGEncrypt.encrypt(MSGEncrypt.keyToString(secKey), oldPuc));
                                }

                                //Don't send message if client got the password wrong
                                if(running){
                                    init = false;
                                    broadcast("Welcome " + client.getName(), true, false);
                                }
                            } else{
                                if(inputLine.startsWith("!name")) {
                                    String oldName = client.getName();
                                    String newName = inputLine.replace("!name ", "");
                                    while(newName.startsWith("!")) newName = newName.substring(1);
                                    client.setName(newName);
                                    broadcast(oldName + " has changed their name to " + client.getName(), true, false);
                                }
                            }
                            continue;
                        }
                        inputLine = client.getName() + ": " + inputLine;
                        broadcast(inputLine, false, true);
                    }
                }
            } catch (Exception e){
                e.printStackTrace();
            }
        }

        void broadcast(String input, Boolean broadcastToSender, Boolean broadcastAsSender){
            try {
                if (!broadcastAsSender) input = "Server: " + input;
                System.out.println(input);
                if(!(mode==M_CDE)) input = MSGEncrypt.AESEncrypt(input, secKey);
                String inputX = input;
                for (Member client1 : clientList) {
                    if(mode==M_CDE){
                        inputX = MSGEncrypt.AESEncrypt(input, client1.getSecretKey());
                    }
                    if (broadcastToSender) client1.getWriter().println(inputX);
                    else if (client1 != client) client1.getWriter().println(inputX);
                }
            } catch(Exception e){
                e.printStackTrace();
            }
        }
    }
}