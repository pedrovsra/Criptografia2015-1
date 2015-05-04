import java.nio.charset.Charset;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

public static void main(String[] args) throws Exception {
    
    //byte[] keyBytes = new byte[] { (byte)0x36,(byte)0xf1,(byte)0x83,(byte)0x57,(byte)0xbe,(byte)0x4d,(byte)0xbd,(byte)0x77,(byte)0xf0,(byte)0x50,(byte)0x51,(byte)0x5c,0x73,(byte)0xfc,(byte)0xf9,(byte)0xf2};
    byte[] keyBytes = hexStringToByteArray("36f18357be4dbd77f050515c73fcf9f2");
	//IV 16 bits (préfixe du cipherText)
    //byte[] ivBytes = new byte[] {(byte)0x69,(byte)0xdd,(byte)0xa8,(byte)0x45,(byte)0x5c,(byte)0x7d,(byte)0xd4,(byte)0x25,(byte)0x4b,(byte)0xf3,(byte)0x53,(byte)0xb7,(byte)0x73,(byte)0x30,(byte)0x4e,(byte)0xec};
    byte[] ivBytes = hexStringToByteArray("770b80259ec33beb2561358a9f2dc617");
    //Initialisation
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

    //Mode
    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    byte[] cipherText = hexStringToByteArray("e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451");
    //byte[]  cipherText = new byte[] {(byte)0x0e,(byte)0xc7,(byte)0x70,(byte)0x23,(byte)0x30,(byte)0x09,(byte)0x98,(byte)0xce,(byte)0x7f,(byte)0x75,(byte)0x20,(byte)0xd1,(byte)0xcb,(byte)0xbb,(byte)0x20,(byte)0xfc,(byte)0x38,(byte)0x8d,(byte)0x1b,(byte)0x0a,(byte)0xdb,(byte)0x50,(byte)0x54,(byte)0xdb,(byte)0xd7,(byte)0x37,(byte)0x08,(byte)0x49,(byte)0xdb,(byte)0xf0,(byte)0xb8,(byte)0x8d,(byte)0x39,(byte)0x3f,(byte)0x25,(byte)0x2e,(byte)0x76,(byte)0x4f,(byte)0x1f,(byte)0x5f,(byte)0x7a,(byte)0xd9,(byte)0x7e,(byte)0xf7,(byte)0x9d,(byte)0x59,(byte)0xce,(byte)0x29,(byte)0xf5,(byte)0xf5,(byte)0x1e,(byte)0xec,(byte)0xa3,(byte)0x2e,(byte)0xab,(byte)0xed,(byte)0xd9,(byte)0xaf,(byte)0xa9,(byte)0x32,(byte)0x29}; 
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);  
    byte [] original = cipher.doFinal(cipherText);
    String plaintext = new String(original);
    System.out.println("plaintext: " + plaintext );
    }
    
    public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}
}