package simplechatrsa;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;

/**
 *
 * @author cesar
 */
public class Client {

    public static void main(String[] args) throws Exception {
        Socket sock = new Socket("127.0.0.1", 3000);
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
        OutputStream ostream = sock.getOutputStream();
        PrintWriter pwrite = new PrintWriter(ostream, true);

        InputStream istream = sock.getInputStream();
        BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));
        
        // Generate keys with 1024 bits
        RSA.generateKeys(RSA.BIT_NUM);
        System.out.println("Keys generated!");
        /*System.out.println("Client keys:");
        System.out.println("Public:\n" + RSA.pubKey.toString());
        System.out.println("Private:\n" + RSA.secKey.toString());*/

        // Sending Public Key
        pwrite.println(RSA.pubKey.getSendValue());
        pwrite.flush();
        System.out.println("Public Key Sent!");
        
        // Receiving Server Public Key
        String keyStream;
        EncryptionKey serverPublicKey = null;
        if ((keyStream = receiveRead.readLine()) != null) {
            System.out.println("Received Server Public Key!");
            String[] keysStr = keyStream.split(",");
            serverPublicKey = new EncryptionKey(RSA.valueToBigInteger(keysStr[0]),RSA.valueToBigInteger(keysStr[1]));
        }
        
        System.out.println("Start the chat");

        String receiveMessage, sendMessage, decryptedMessage;
        BigInteger encryptedMessageBI,decryptedMessageBI;
        while (true) {
            System.out.print("client> ");
            sendMessage = keyRead.readLine();  // keyboard reading
            encryptedMessageBI = RSA.encrypt(RSA.messageToBigInteger(sendMessage), RSA.secKey); // Encrypt the message
            pwrite.println(encryptedMessageBI);       // sending to server
            pwrite.flush();                    // flush the data
            if ((receiveMessage = receiveRead.readLine()) != null) //receive from server
            {
                System.out.println("server-encrypted> " + receiveMessage);
                decryptedMessageBI = RSA.decrypt(RSA.valueToBigInteger(receiveMessage), serverPublicKey);
                decryptedMessage = RSA.messageToString(decryptedMessageBI);
                System.out.println("server-decrypted> " + decryptedMessage);
            }
        }
    }
}
