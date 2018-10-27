package com.luszczyk;

import javax.crypto.SecretKey;
import java.io.PrintWriter;
import java.net.Socket;

class Member {
    private PrintWriter writer;
    private String name;
    private Socket clientSocket;
    private SecretKey secretKey;

    void setWriter(PrintWriter write) {
        this.writer = write;
    }

    PrintWriter getWriter(){
        return this.writer;
    }

    void setName(String newName) {
        this.name = newName;
    }

    String getName(){
        return this.name;
    }

    void setSocket(Socket socket){
        this.clientSocket = socket;
    }

    Socket getSocket(){
        return this.clientSocket;
    }

    void setSecretKey(SecretKey secretKey){
        this.secretKey = secretKey;
    }

    SecretKey getSecretKey(){
        return this.secretKey;
    }
}
