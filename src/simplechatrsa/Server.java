package simplechatrsa;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

/**
 *
 * @author cesar
 */
public class Server {

    public static void main(String[] args) throws Exception {
        ServerSocket sersock = new ServerSocket(3000);

        // Generate keys with 1024 bits
        RSA.generateKeys(RSA.BIT_NUM);
        System.out.println("Keys generated!");
        /*System.out.println("Server keys:");
        System.out.println("Public:\n" + RSA.pubKey.toString());
        System.out.println("Private:\n" + RSA.secKey.toString());*/

        System.out.println("Server  ready for chatting");
        Socket sock = sersock.accept();
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
        OutputStream ostream = sock.getOutputStream();
        PrintWriter pwrite = new PrintWriter(ostream, true);
        InputStream istream = sock.getInputStream();
        BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

        // Receiving Client Public Key
        String keyStream;
        EncryptionKey clientPublicKey = null;
        if ((keyStream = receiveRead.readLine()) != null) {
            System.out.println("Received Client Public Key!");
            String[] keysStr = keyStream.split(",");
            clientPublicKey = new EncryptionKey(RSA.valueToBigInteger(keysStr[0]),RSA.valueToBigInteger(keysStr[1]));
        }
        
        // Sending Public Key
        pwrite.println(RSA.pubKey.getSendValue());
        pwrite.flush();
        System.out.println("Public Key Sent!");

        String receiveMessage, sendMessage, decryptedMessage;
        BigInteger decryptedMessageBI,encryptedMessageBI;
        while (true) {
            if ((receiveMessage = receiveRead.readLine()) != null) {
                System.out.println("client-encrypted> " + receiveMessage);
                decryptedMessageBI = RSA.decrypt(RSA.valueToBigInteger(receiveMessage), clientPublicKey);
                decryptedMessage = RSA.messageToString(decryptedMessageBI);
                System.out.println("client-decrypted> " + decryptedMessage);
            }
            System.out.print("server> ");
            sendMessage = keyRead.readLine();
            encryptedMessageBI = RSA.encrypt(RSA.messageToBigInteger(sendMessage), RSA.secKey);
            pwrite.println(encryptedMessageBI);
            pwrite.flush();
        }
    }
}
