import org.springframework.util.StringUtils;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class SignUtils {

    public static String privateKeyPath = "C:\\private.bin";
    public static String publicKeyPath = "C:\\public.bin";
    public static String signatureAlgorithm = "SHA256withRSA";
//    public static String signatureAlgorithm = "MD5withRSA";
    public static int keySize = 2048;
//    public static int keySize = 1024;
    public static KeyPair KeyPairObj = null;

    public static void main(String[] args){
        generateKeyPairs();
        String message = "signature messages";
        String signature = doSignPrivateKey(message);
        System.out.println(signature);
        System.out.println(doVerifyPublicKey(message, signature));
    }

    public static byte[] sign(byte[] data, int offset, int length, byte[] privateKeyBytes){
        byte[] signedData = null;
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(data, offset, length);
            signedData = signature.sign();
        } catch (Exception e){
            e.printStackTrace();
        }
        return signedData;
    }

    public static String getKey(String keyPath){
        StringBuilder result = new StringBuilder();
        try{
            File file = new File(keyPath);
            BufferedReader br = new BufferedReader(new FileReader(file));//构造一个BufferedReader类来读取文件
            String s = null;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                result.append(System.lineSeparator()+s);
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
        return result.toString();
    }

    public static String doSignPrivateKey(String data){
        String dataBack = "";
        try{
            if (!StringUtils.isEmpty(data)){
                byte[] Bytes = sign(data.getBytes(), 0, data.getBytes().length, (new BASE64Decoder()).decodeBuffer(getKey(privateKeyPath)));
                dataBack = (new BASE64Encoder()).encodeBuffer(Bytes);
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        return dataBack;
    }

    public static void generateKeyPairs(){
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            KeyPair keyPair = generator.generateKeyPair();
            KeyPairObj = keyPair;
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            writeKey(publicKeyPath, publicKey);
            writeKey(privateKeyPath, privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void writeKey(String path, Key key) throws Exception {
        FileOutputStream fos = new FileOutputStream(path);
        byte[] keyBytes = key.getEncoded();
        String keyString = (new BASE64Encoder()).encodeBuffer(keyBytes);
        fos.write(keyString.getBytes());
        fos.close();
    }

    public static boolean verify(byte[] data, int offset, int length, byte[] publicKeyBytes, byte[] dataSignature) {
        boolean result = false;
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(publicKey);
            signature.update(data, offset, length);
            result = signature.verify(dataSignature);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }

    public static boolean doVerifyPublicKey(String data, String sign) {
        Boolean returnFlag = Boolean.FALSE;
        if ((StringUtils.isEmpty(data)) || (StringUtils.isEmpty(sign))) {
            return Boolean.FALSE.booleanValue();
        }
        try {
            returnFlag = Boolean.valueOf(verify(data.getBytes(), 0,data.getBytes().length,(new BASE64Decoder()).decodeBuffer(getKey(publicKeyPath)), (new BASE64Decoder()).decodeBuffer(sign)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return returnFlag.booleanValue();
    }
}
