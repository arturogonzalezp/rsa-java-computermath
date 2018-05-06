package simplechatrsa;

import java.math.BigInteger;

/**
 *
 * @author cesar
 */
public class EncryptionKey {

    private BigInteger number, modulus;

    public EncryptionKey(BigInteger number, BigInteger modulus){
        this.number = number;
        this.modulus = modulus;
    }

    public void setNumber(BigInteger number) {
        this.number = number;
    }

    public BigInteger getNumber(){
        return number;
    }

    public BigInteger getModulus(){
            return modulus;
    }
    public String getSendValue(){
        return "" + number + "," + modulus;
    }
    public String toString(){
        return ("number " + number + '\n' + "modulus " + modulus);
    }

}