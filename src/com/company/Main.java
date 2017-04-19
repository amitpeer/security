package com.company;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class Main {

    static final int BLOCK_SIZE = 10;

    public static void main(String[] args) {
        String pathToKey = "C:\\securityExamples\\key_example.txt";
        String pathToText = "C:\\securityExamples\\plainMsg_example.txt";
        String pathToVector = "C:\\securityExamples\\IV_example.txt";
        String pathToEncryptionText = "C:\\securityExamples\\my_cipher.txt";
        String pathToDecryptionText = "C:\\securityExamples\\my_text.txt";

        //part a testing
//        writeByteArrayListToFile(pathToEncryptionText, subCbcEncryption(pathToText, pathToVector,
//                                                                        pathToKey, BLOCK_SIZE));
//        writeByteArrayListToFile(pathToDecryptionText, subCbcDecryption(pathToEncryptionText, pathToVector,
//                                                                        pathToKey, BLOCK_SIZE));
        Set<String> set = generatePerm("abcdefgh");
        for( String permo : set)
            System.out.println(permo);


        //part b testing

    }

    //Part A.a
    private static ArrayList<byte[]> subCbcEncryption(String textPath, String vectorPath, String keyPath, int
            blockSize) {
        byte[] text = readFileToByteArray(textPath);
        byte[] vector = readFileToByteArray(vectorPath);
        HashMap<Byte, Byte> key = readKeyToHashMap(keyPath);
        ArrayList<byte[]> textList = createByteList(text, blockSize);
        ArrayList<byte[]> cipher = new ArrayList<>(); //eventually this will hold the encrypted text

        //start CBC Encryption
        for (byte[] plainText : textList) {

            //do XOR for each byte with vector
            ArrayList<Byte> xorList = new ArrayList<>();
            for (int i = 0; i < blockSize; i++) {
                xorList.add((byte) (plainText[i] ^ vector[i]));
            }

            //do encryption function using the given key
            byte[] cipherText = new byte[blockSize];
            int index = 0;
            for (byte b : xorList) {
                cipherText[index] = key.getOrDefault(b, b);
                index++;
            }
            cipher.add(cipherText);

            //change vector to the last encrypted text for the next iteration
            vector = cipherText;
        }
        return cipher;
    }

    //Part A.b
    private static ArrayList<byte[]> subCbcDecryption(String cipherPath, String vectorPath, String keyPath, int
            blockSize) {
        byte[] cipher = readFileToByteArray(cipherPath);
        byte[] vector = readFileToByteArray(vectorPath);
        HashMap<Byte, Byte> key = readKeyToHashMap(keyPath);

        //Reverse key for decryption
        Map<Byte, Byte> decryptionKey = new HashMap<>();
        for (Map.Entry<Byte, Byte> entry : key.entrySet()) {
            decryptionKey.put(entry.getValue(), entry.getKey());
        }

        ArrayList<byte[]> cipherList = createByteList(cipher, blockSize);
        ArrayList<byte[]> text = new ArrayList<>(); //eventually this will hold the decrypted text

        //start CBC Decryption
        for (byte[] cipherText : cipherList) {

            //do decryption function using the given key
            byte[] plainText = new byte[blockSize];
            int index = 0;
            for (byte b : cipherText) {
                plainText[index] = decryptionKey.getOrDefault(b, b);
                index++;
            }

            //do XOR
            for (int i = 0; i < blockSize; i++) {
                plainText[i] = (byte) (plainText[i] ^ vector[i]);
            }
            text.add(trim(plainText));

            //change vector to the cipherText for the next iteration
            vector = cipherText;
        }

        return text;
    }

    //creates a list of byte array.
    //each byte array is in the size of blockSize
    private static ArrayList<byte[]> createByteList(byte[] text, int blockSize) {
        ArrayList<byte[]> byteList = new ArrayList<>();
        int counter = 0;
        boolean isLastInserted = false;
        byte[] byteArray = new byte[blockSize];
        for (byte b : text) {
            isLastInserted = false;
            if (counter == blockSize) {
                counter = 0;
                byteList.add(byteArray);
                byteArray = new byte[blockSize];
                isLastInserted = true;
            }
            byteArray[counter] = b;
            counter++;
        }
        if (!isLastInserted) {
            byteList.add(byteArray);
        }
        return byteList;
    }

    //write to file function
    private static void writeByteArrayListToFile(String path, ArrayList<byte[]> byteArrayList) {
        String cipherString = "";
        for (byte[] plainText : byteArrayList) {
            cipherString += new String(plainText);
        }
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(path))) {
            writer.write(cipherString);
        } catch (IOException ex) {
            System.out.println(
                    "Error reading file '"
            );
        }
    }

    //creates the encryption key
    private static HashMap<Byte, Byte> readKeyToHashMap(String keyPath) {
        HashMap<Byte, Byte> key = new HashMap<>();
        byte[] keyArray = readFileToByteArray(keyPath);
        ArrayList<Byte> keyList = new ArrayList<>();

        //remove all non-character
        for (byte k : keyArray) {
            if (k >= 65) {
                keyList.add(k);
            }
        }

        //insert to dictionary
        for (int i = 0; i < keyList.size() - 1; i += 2) {
            key.put(keyList.get(i), keyList.get(i + 1));
        }
        return key;
    }

    //reads a text file into byte array
    private static byte[] readFileToByteArray(String path) {
        byte[] data = null;
        Path fileLocation = Paths.get(path);
        try {
            data = Files.readAllBytes(fileLocation);
        } catch (IOException e) {
            System.out.println("Error reading file '" + path + "'");
        }
        return data;
    }

    //reads text file to string
    private static String readFileToString(String fileName) {
        String line;
        String text = "";

        try {
            FileReader fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            while ((line = bufferedReader.readLine()) != null) {
                text += line;
            }
            bufferedReader.close();
        } catch (FileNotFoundException ex) {
            System.out.println(
                    "Unable to open file '" +
                            fileName + "'");
        } catch (IOException ex) {
            System.out.println(
                    "Error reading file '"
                            + fileName + "'");
        }

        return text;
    }

    private static byte[] trim(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            --i;
        }

        return Arrays.copyOf(bytes, i + 1);
    }



    //part b
    //brute force attack
    private static void cipher_textOnlyAttack(String cipherTextPath, String vectorPath)
    {
        byte[] cipher = readFileToByteArray(cipherTextPath);
        byte[] vector = readFileToByteArray(vectorPath);
        char[] permutation = "abcdefgh".toCharArray();
        HashMap<Byte, Byte> potentialKeyMap = null;
        Set<String> allKeysSet = generatePerm("abcdefgh");  //8! permo  =  40320
        for(String potentialKey : allKeysSet)
        {
            int permoIndex = 0;
            potentialKeyMap = new HashMap<>();
            //create from each permutation a potential key
            for(char ch : potentialKey.toCharArray())
            {
                String keyChar = potentialKey.substring(0,1);
                byte[] keyMap = keyChar.getBytes();
                byte[] valueMap = (""+ch).getBytes();
                potentialKeyMap.put(keyMap[0],valueMap[0]);
            }
            //now check the key
            if(checkKeyOnCipher(cipher,potentialKeyMap,vector))
            {
                writeKeyToFile(potentialKeyMap);
                return;
            }
        }

    }
    //check the key - reduceMap needed
    private static boolean checkKeyOnCipher(byte[] cipher,HashMap<Byte, Byte> potentialKeyMap , byte[] vector )
    {
        boolean ans = false;
        return ans;

    }

    //write key to file
    private static void writeKeyToFile(HashMap<Byte, Byte> potentialKeyMap)
    {

    }

    public static Set<String> generatePerm(String input)
    {
        Set<String> set = new HashSet<String>();
        if (input == "")
            return set;
        Character a = input.charAt(0);
        if (input.length() > 1)
        {
            input = input.substring(1);
            Set<String> permSet = generatePerm(input);
            for (String x : permSet)
            {
                for (int i = 0; i <= x.length(); i++)
                {
                    String toAdd = x.substring(0, i) + a + x.substring(i);
                    set.add(toAdd);
                }
            }
        }
        else
        {
            set.add(a + "");
        }
        return set;
    }

}
