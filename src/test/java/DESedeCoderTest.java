import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.tzg.encryptDomo.DESedeCoder;
import static org.junit.Assert.assertEquals;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class DESedeCoderTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    @Test
    public final void test() throws Exception {
        Provider provider = Security.getProvider("BC");
        System.out.println(provider);
        String inputStr = "DESede";
        byte[] inputData = inputStr.getBytes();
        System.out.println("原文:\t" + inputStr);
        byte[] key = DESedeCoder.initKey();
        System.out.println("密钥： \t" + Base64.encodeBase64String(key));
        System.out.println(key.length);
        //自定义key
        key = "REVTZWRlREVTZWRlREVTZWRlREVTZWRl".getBytes();

        //System.out.println(new String(key));

        //加密
        inputData = DESedeCoder.encrypt(inputData, key);
        System.out.println("加密后： \t" + Base64.encodeBase64String(inputData));
        //解密
        byte[] outputData = DESedeCoder.decrypt(inputData, key);
        String outputStr = new String(outputData);

        System.out.println("解密后：\t" + outputStr);
        assertEquals(inputStr, outputStr);
    }
}
