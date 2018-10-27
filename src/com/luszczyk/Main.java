package com.luszczyk;

import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Run as Client [C] or Server [S]? ");
        String input = scanner.next().toLowerCase();
        while(!(input.equals("c")||input.equals("s"))) {
            input = scanner.next().toLowerCase();
        }
        if(input.equals("c")) {
            Client client = new Client();
            System.out.print("Enter IP address: ");
            try {
                client.start(scanner.next());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            Server server = new Server();
            System.out.print("Select server mode: Encrypted [E], Client-Dependent Encrypted [C] or Password-Protected [P]: ");
            input = scanner.next().toLowerCase();
            while(!(input.equals("e")||input.equals("c")||input.equals("p"))) {
                input = scanner.next().toLowerCase();
            }
            Integer mode = 0;
            switch(input){
                case "e":
                    mode = 0;
                    break;
                case "c":
                    mode = 1;
                    break;
                case "p":
                    mode = 2;
                    break;
            }
            try {
                server.start(mode);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
