import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

public class Terminal {
    private PublicKey PublicKey;
    private PrivateKey PrivateKey;

    String CURRENT_DIRECTARY = System.getProperty("user.dir");
    String OUTPUTPACKAGE = CURRENT_DIRECTARY + "/src/TestOut/";
    String INPUTPACKAGE = CURRENT_DIRECTARY + "/src/TestInput/";

    public void Terminal() {
        int op;
        do {
            System.out.println("Terminal Security Test:\n");
            System.out.println("1-Generate Keys:\n");
            System.out.println("2-Store Key in file:\n");
            System.out.println("3-Encrypt file with key:\n");
            System.out.println("4-Decrypt file with key:\n");
            System.out.println("5-Sign File with key:\n");
            System.out.println("0-Leave:\n");
            System.out.println("Insert number:");

            try {
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(System.in));
                String read= reader.readLine();
                op= Integer.parseInt(read);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            switch (op) {
                case 1 -> createkeys();
                case 2 -> storeKeys();
                case 3 -> encriptfile();
                case 4 -> decriptfile();
                case 5 -> Signencriptfile();
                case 0 -> {
                    return;
                }
            }
        } while (op != 0);
    }

    private void Signencriptfile() {
        File File_Path = new File(INPUTPACKAGE+"InputText.txt");

        System.out.println("Beginning Encrypting Process\n");
        FileInputStream File_Input_Stream;
        try {
            File_Input_Stream = new FileInputStream(File_Path);
            byte[] Demo_Array = new byte[(int)File_Path.length()];
            File_Input_Stream.read(Demo_Array);
            System.out.println("Read file:\n"+ Arrays.toString(Demo_Array) +"\n");
            File_Input_Stream.close();
            System.out.println("Close File Input Stream\n");

            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(PrivateKey);
            privateSignature.update(Demo_Array);
            byte[] signature = privateSignature.sign();
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(PublicKey);
            publicSignature.update(Demo_Array);

            boolean isCorrect = publicSignature.verify(signature);
            System.out.println("Signature correct: " + isCorrect);

            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, PublicKey);

            Cipher decriptCipher = Cipher.getInstance("RSA");
            decriptCipher.init(Cipher.DECRYPT_MODE, PrivateKey);

            byte[] cipherText = encryptCipher.doFinal(Demo_Array);

            String decipheredMessage = new String(decriptCipher.doFinal(cipherText), StandardCharsets.UTF_8);

            System.out.println(decipheredMessage);

        } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 BadPaddingException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private void decriptfile() {
        byte[] encryptedFileBytes = new byte[0];
        try {
            encryptedFileBytes = Files.readAllBytes(Path.of(OUTPUTPACKAGE + "Textencr.txt"));
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, PrivateKey);
            byte[] decryptedFileBytes = decryptCipher.doFinal(encryptedFileBytes);
            try (FileOutputStream stream = new FileOutputStream(OUTPUTPACKAGE+"Textdencr.txt")) {
                stream.write(decryptedFileBytes);
            }
        } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private void encriptfile() {
        File File_Path = new File(INPUTPACKAGE+"InputText.txt");
        // Instance of the FileInputStream
        System.out.println("Beginning Encrypting Process\n");
        FileInputStream File_Input_Stream = null;
        try {
            File_Input_Stream = new FileInputStream(File_Path);
            byte[] Demo_Array = new byte[(int)File_Path.length()];
            File_Input_Stream.read(Demo_Array);
            System.out.println("Read file:\n"+ Arrays.toString(Demo_Array) +"\n");
            File_Input_Stream.close();
            System.out.println("Close File Input Stream\n");
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, PublicKey);
            System.out.println("Encrypting file with public key. Type RSA\n");
            byte[] encryptedFileBytes = encryptCipher.doFinal(Demo_Array);
            try (FileOutputStream stream = new FileOutputStream(OUTPUTPACKAGE+"Textencr.txt")) {
                stream.write(encryptedFileBytes);
            }
            System.out.println("Placed file.\n");
        } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private void storeKeys() {
        try (FileOutputStream fos = new FileOutputStream(OUTPUTPACKAGE+"public.key")) {
            fos.write(PublicKey.getEncoded());
            System.out.println("Wrote Public key in file\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try (FileOutputStream fos = new FileOutputStream(OUTPUTPACKAGE+"private.key")) {
            fos.write(PrivateKey.getEncoded());
            System.out.println("Wrote Private key in file\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    private void createkeys() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            PublicKey= pair.getPublic();
            PrivateKey = pair.getPrivate();
            System.out.println("Generated keys.\n");
            System.out.println("Public Key: " + pair.getPublic());
            System.out.println("Private Key: " + pair.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }


    }
}
