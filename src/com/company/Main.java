package com.company;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Main {

    static final int BLOCK_SIZE = 10;
    static final HashSet<ArrayList<Byte>> WORDS = new HashSet<>();

    public static void main(String[] args) {
        String pathToKey = "C:\\securityExamples\\key_example.txt";
        String pathToText = "C:\\securityExamples\\plainMsg_example.txt";
        String pathToVector = "C:\\securityExamples\\IV_example.txt";
        String pathToEncryptionText = "C:\\securityExamples\\my_cipher.txt";
        String pathToDecryptionText = "C:\\securityExamples\\my_text.txt";
        String pathToCipher = "C:\\securityExamples\\additional_examples\\PartB\\cipher.txt";
        String pathToVectorAttack = "C:\\securityExamples\\additional_examples\\PartB\\IV_short.txt";

        //part a testing
        //        writeByteArrayInArrayListToFile(pathToEncryptionText, subCbcEncryption(pathToText, pathToVector,
        //                                                                        pathToKey, BLOCK_SIZE));
        //        writeByteArrayInArrayListToFile(pathToDecryptionText, subCbcDecryption(pathToEncryptionText, pathToVector,
        //                                                                        pathToKey, BLOCK_SIZE));
        //        Set<String> set = generatePerm("abcdefgh");
        //        for (String permo : set)
        //            System.out.println(permo);

        //part b testing
        cipherTextOnlyAttack(pathToCipher, pathToVectorAttack);
    }

    //Part A.a
    private static ArrayList<byte[]> subCbcEncryption(byte[] text, byte[] vector, HashMap<Byte, Byte> key,
                                                      int blockSize) {
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
    private static ArrayList<byte[]> subCbcDecryption(byte[] cipher, byte[] vector, HashMap<Byte, Byte> key,
                                                      int blockSize) {
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

    //part B - brute force attack
    private static void cipherTextOnlyAttack(String cipherTextPath, String vectorPath) {
        loadDictionaryToMemory();
        String pathToSave = "C:\\securityExamples\\additional_examples\\PartB\\my_key.txt";
        byte[] cipher = readFileToByteArray(cipherTextPath);
        byte[] vector = readFileToByteArray(vectorPath);
        char[] permutation = "abcdefgh".toCharArray();
        HashMap<Byte, Byte> potentialKeyMap = null;
        Set<String> allKeysSet = generatePerm("abcdefgh");  //8! permo  =  40320
        for (String potentialKey : allKeysSet) {
            int permoIndex = 0;
            potentialKeyMap = new HashMap<>();
            //create from each permutation a potential key
            for (char ch : potentialKey.toCharArray()) {
                String keyChar = potentialKey.substring(0, 1);
                byte[] keyMap = keyChar.getBytes();
                byte[] valueMap = ("" + ch).getBytes();
                potentialKeyMap.put(keyMap[0], valueMap[0]);
            }
            //now check the key
            if (checkKeyOnCipher(cipher, potentialKeyMap, vector)) {
                writeKeyToFile(potentialKeyMap, pathToSave);
                return;
            }
        }
    }

    //check the given key
    private static boolean checkKeyOnCipher(byte[] cipher, HashMap<Byte, Byte> potentialKey, byte[] vector) {
        boolean isCorrectKey = false;

        //Decrypt text using the potential key
        ArrayList<byte[]> text = subCbcDecryption(cipher, vector, potentialKey, BLOCK_SIZE);

        //Put all words in one array list (because the arrays in text are in the size of block_size each)
        ArrayList<Byte> allWords = new ArrayList<>();
        for (byte[] bArray : text) {
            for (byte b : bArray) {
                allWords.add(b);
            }
        }

        //Make HashSet of words out of the decrypted text (32 separates between words)
        HashSet<ArrayList<Byte>> words = new HashSet<>();
        ArrayList<Byte> word = new ArrayList<>();
        for (byte b : allWords) {
            if (b >=65) {
                word.add(b);
            } else {
                words.add(word);
                word = new ArrayList<>();
            }
        }

        //check if the words are in english using the English dictionary loaded to memory
        long numberOfEnglishWords = words.stream().filter(WORDS::contains).count();
        if (numberOfEnglishWords >= (long) words.size() / 2) {
            isCorrectKey = true;
        }
        return isCorrectKey;
    }

    private static void loadDictionaryToMemory() {
        //load english dictionary to byte array
        byte[] words = readFileToByteArray("src/com/company/words2.txt");

        //make int array list and remove empty entries
        ArrayList<Byte> wordsIntList = new ArrayList<>();
        for (byte b : words) {
            if (b >= 65 || b == 13) {
                wordsIntList.add(b);
            }
        }

        //split for words by the new line delimiter (13)
        ArrayList<Byte> word = new ArrayList<>();
        for (byte b : wordsIntList) {
            if (b != 13) { //new line delimiters
                word.add(b);
            } else {
                WORDS.add(word);
                word = new ArrayList<>();
            }
        }
    }

    //write key to file
    private static void writeKeyToFile(HashMap<Byte, Byte> potentialKeyMap, String path) {
        writeByteArrayListToFile(new ArrayList<Byte>(potentialKeyMap.keySet()), path);
        writeByteArrayListToFile(new ArrayList<Byte>(potentialKeyMap.values()), path);
    }

    private static void writeByteArrayListToFile(ArrayList<Byte> bytes, String path) {
        String toWrite;
        byte[] byteArray = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            byteArray[i] = bytes.get(i);
        }
        toWrite = new String(byteArray);
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(path))) {
            writer.write(toWrite);
        } catch (IOException ex) {
            System.out.println(
                    "Error reading file '"
            );
        }
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
    private static void writeByteArrayInArrayListToFile(ArrayList<byte[]> byteArrayList, String path) {
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
            if (k >= 41) {
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

    private static Set<String> generatePerm(String input) {
        Set<String> set = new HashSet<String>();
        if (input == "")
            return set;
        Character a = input.charAt(0);
        if (input.length() > 1) {
            input = input.substring(1);
            Set<String> permSet = generatePerm(input);
            for (String x : permSet) {
                for (int i = 0; i <= x.length(); i++) {
                    String toAdd = x.substring(0, i) + a + x.substring(i);
                    set.add(toAdd);
                }
            }
        } else {
            set.add(a + "");
        }
        return set;
    }
}
