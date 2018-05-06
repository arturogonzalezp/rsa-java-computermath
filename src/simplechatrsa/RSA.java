package simplechatrsa;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;

/**
 *
 * @author cesar
 */
public class RSA{
    public static final int BIT_NUM = 1024;
    private static final Charset CHARSET = Charset.forName("UTF-8");
    private static BigInteger modulus;
    public static EncryptionKey pubKey, secKey;

    public static void generateKeys(int nBits){
        BigInteger prime1, prime2, phi, secretNumber, publicNumber;
        SecureRandom random = new SecureRandom();
        prime1 = BigInteger.probablePrime(nBits, random);
        prime2 = BigInteger.probablePrime(nBits, random);
        modulus = prime1.multiply(prime2);
        phi = prime1.subtract(BigInteger.ONE).multiply(prime2.subtract(BigInteger.ONE));
        publicNumber = BigInteger.probablePrime(nBits, random); //first part of the Public EncryptionKey
        secretNumber = publicNumber.modInverse(phi); // first part of the Secret EncryptionKey
        pubKey = new EncryptionKey(publicNumber, modulus);
        secKey = new EncryptionKey(secretNumber, modulus);
    }
    public static BigInteger encrypt(BigInteger message, EncryptionKey pubKey){

        return message.modPow(pubKey.getNumber(), pubKey.getModulus());

    }
    public static BigInteger decrypt(BigInteger encryptedMessage, EncryptionKey secKey){
        return encryptedMessage.modPow(secKey.getNumber(), secKey.getModulus());
    }
    public static BigInteger messageToBigInteger(String message){
        byte[] bytes = message.getBytes();
        BigInteger BIMessage =  new BigInteger(1, bytes);
        return BIMessage;
    }
    public static BigInteger valueToBigInteger(String message){
        BigInteger BIMessage = new BigInteger(message);
        return BIMessage;
    }
    public static String messageToString(BigInteger BIMessage){
       byte[] bytes = BIMessage.toByteArray();
       String message = new String(bytes);
       return message;
    }
}