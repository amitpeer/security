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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

public class Main {

    private static final HashSet<ArrayList<Byte>> WORDS = new HashSet<>();
    private static HashMap<Byte, Byte> bestKey = new HashMap<>();
    private static int blockSize = 8128;
    private static int permotationNumber = 0;
    private static int maximumWordsFromKey = 0;

    public static void main(String[] args) {

        //        test();

        List<String> argsList = Arrays.asList(args);
        String algorithm = argsList.get(argsList.indexOf("-a") + 1);
        String action = argsList.get(argsList.indexOf("-c") + 1);
        String pathToText = argsList.get(argsList.indexOf("-t") + 1);
        String pathToKey = argsList.get(argsList.indexOf("-k") + 1);
        String pathToVector = argsList.get(argsList.indexOf("-v") + 1);
        String pathToWrite = argsList.get(argsList.indexOf("-o") + 1);

        byte[] text = readFileToByteArray(pathToText);
        byte[] vector = readFileToByteArray(pathToVector);
        HashMap<Byte, Byte> key = !pathToKey.equals("-a") ? readKeyToHashMap(pathToKey) : null;

        if (algorithm.equals("sub_cbc_10")) {
            blockSize = 10;
        } else if (algorithm.equals("sub_cbc_52")) {
            blockSize = 8128;
        }
        if (action.equals("encryption")) {
            writeByteArrayInArrayListToFile(subCbcEncryption(text, vector, key), pathToWrite);
            if (action.equals("decryption")) {
                writeByteArrayInArrayListToFile(subCbcDecryption(text, vector, key), pathToWrite);
            }
            if (action.equals("attack") && algorithm.equals("sub_cbc_10")) {
                cipherTextOnlyAttack(text, vector, pathToWrite);
            } else if (action.equals("attack") && algorithm.equals("sub_cbc_52")) {
                // part C.2
            }
        }
    }

    private static void test() {
        String pathToKey = "C:\\securityExamples\\examples_ascii\\PartB\\key_short.txt";
        String pathToText = "C:\\securityExamples\\plainMsg_example.txt";

        String pathToEncryptionText = "C:\\securityExamples\\additional_examples\\PartB\\my_cipher.txt";
        String pathToDecryptionText = "C:\\securityExamples\\my_text.txt";
        String pathToCipher = "C:\\securityExamples\\examples_ascii\\PartB\\cipher.txt";
        String pathToVectorAttack = "C:\\securityExamples\\examples_ascii\\PartB\\IV_short.txt";

        //part a testing
        HashMap<Byte, Byte> key = readKeyToHashMap(pathToKey);
        byte[] vector = readFileToByteArray(pathToVectorAttack);
        byte[] cipher = readFileToByteArray(pathToCipher);

        //                writeByteArrayInArrayListToFile(pathToEncryptionText, subCbcEncryption(pathToText, pathToVector,
        //                                                                                pathToKey, blockSize));
        //        writeByteArrayInArrayListToFile(subCbcDecryption(cipher, vector, key, blockSize),pathToDecryptionText);

        //part b testing
        //        cipherTextOnlyAttack(pathToCipher, pathToVectorAttack);
        //        writeByteArrayInArrayListToFile(subCbcDecryption(cipher, vector, bestKey, blockSize), pathToDecryptionText);

        //part c testing
        String pathToCAKey = "C:\\securityExamples\\examples_ascii\\PartC\\key_long.txt";
        String pathToACVector = "C:\\securityExamples\\examples_ascii\\PartC\\IV_long.txt";
        String pathToCATextToEnc = "C:\\securityExamples\\examples_ascii\\PartC\\known_plain_long.txt";
        String pathToCaEncr = "C:\\securityExamples\\examples_ascii\\PartC\\C_A_Encrypting.txt";
        String pathToCAdecry = "C:\\securityExamples\\examples_ascii\\PartC\\C_A_decrypting.txt";
        byte[] vectorLong = readFileToByteArray(pathToACVector);
        byte[] textLong = readFileToByteArray(pathToCATextToEnc);
        HashMap<Byte, Byte> keyLong = readKeyToHashMap(pathToCAKey);
        writeByteArrayInArrayListToFile(subCbcEncryption(textLong, vectorLong,
                                                         keyLong), pathToCaEncr);

        String pathToCaCipher = "C:\\securityExamples\\examples_ascii\\PartC\\known_cipher.txt";
        writeByteArrayInArrayListToFile(subCbcDecryption(readFileToByteArray(pathToCaCipher), vectorLong,
                                                         keyLong), pathToCAdecry);
    }

    //Part A.a
    private static ArrayList<byte[]> subCbcEncryption(byte[] text, byte[] vector, HashMap<Byte, Byte> key) {
        ArrayList<byte[]> textList = createByteList(text);
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
    private static ArrayList<byte[]> subCbcDecryption(byte[] cipher, byte[] vector, HashMap<Byte, Byte> key) {
        //Reverse key for decryption
        Map<Byte, Byte> decryptionKey = new HashMap<>();
        for (Map.Entry<Byte, Byte> entry : key.entrySet()) {
            decryptionKey.put(entry.getValue(), entry.getKey());
        }

        ArrayList<byte[]> cipherList = createByteList(cipher);
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
    private static void cipherTextOnlyAttack(byte[] cipher, byte[] vector, String pathToWrite) {
        loadDictionaryToMemory();

        char[] keyValue = "abcdefgh".toCharArray();
        HashMap<Byte, Byte> potentialKeyMap = null;
        Set<String> allKeysSet = generatePerm("abcdefgh");  //8! permo  =  40320
        for (String potentialKey : allKeysSet) {
            int keyValueIndex = 0;
            potentialKeyMap = new HashMap<>();
            //create from each permutation a potential key
            for (char ch : potentialKey.toCharArray()) {
                char keyChar = keyValue[keyValueIndex];
                byte[] keyMap = ("" + keyChar).getBytes();
                byte[] valueMap = ("" + ch).getBytes();
                potentialKeyMap.put(keyMap[0], valueMap[0]);
                keyValueIndex++;
            }

            //check the key
            //take only the first 2000 bytes
            ArrayList<Byte> first100PacketsFromCipher = new ArrayList<>();
            for (int i = 0; i <= 2500; i++) {
                if (i < cipher.length) {
                    first100PacketsFromCipher.add(cipher[i]);
                }
            }

            //change list to array
            byte[] first100Array = new byte[first100PacketsFromCipher.size()];
            for (int i = 0; i < first100PacketsFromCipher.size(); i++) {
                first100Array[i] = first100PacketsFromCipher.get(i);
            }

            //check key
            checkKeyOnCipher(first100Array, potentialKeyMap, vector);
        }

        //write the found key to file
        writeKeyToFile(bestKey, pathToWrite);
    }

    //check the given key
    private static boolean checkKeyOnCipher(byte[] cipher, HashMap<Byte, Byte> potentialKey, byte[] vector) {
        boolean isCorrectKey = false;

        //Decrypt text using the potential key
        ArrayList<byte[]> text = subCbcDecryption(cipher, vector, potentialKey);

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
            if (words.size() > 200)
                break;
            if (b >= 65) {
                word.add(b);
            } else {
                words.add(word);
                word = new ArrayList<>();
            }
        }

        //for debag
        permotationNumber++;
        System.out.println(permotationNumber);

        //check if the words are in english using the English dictionary loaded to memory
        //long numberOfEnglishWords = words.stream().filter(WORDS::contains).count();
        int numberOfEnglishWords = 0;
        for (ArrayList<Byte> wordInWords : words) {

            Stream<Byte> capitaleCheck = wordInWords.stream().map(b -> (byte) (b + (byte) 32));
            ArrayList<Byte> capitaleCheckList = new ArrayList<>();
            capitaleCheck.parallel().forEachOrdered(capitaleCheckList::add);

            if (WORDS.contains(wordInWords) || WORDS.contains(capitaleCheckList))
                numberOfEnglishWords++;
        }

        if (numberOfEnglishWords > maximumWordsFromKey) {
            bestKey = new HashMap<>(potentialKey);
            maximumWordsFromKey = numberOfEnglishWords;
        }
        return isCorrectKey;
    }

    private static void loadDictionaryToMemory() {
        //load english dictionary to byte array
        byte[] words = readFileToByteArray("src/com/company/dictionary.txt");

        //make int array list and remove empty entries
        ArrayList<Byte> wordsIntList = new ArrayList<>();
        for (byte b : words) {
            if (b >= 65 || b < 33) {
                wordsIntList.add(b);
            }
        }

        //split for words by the new line delimiter (13)
        ArrayList<Byte> word = new ArrayList<>();
        for (byte b : wordsIntList) {
            if (b > 33) { //new line delimiters
                word.add(b);
            } else {
                WORDS.add(word);
                word = new ArrayList<>();
            }
        }
    }

    //write key to file
    private static void writeKeyToFile(HashMap<Byte, Byte> key, String pathToWrite) {
        //        writeByteArrayListToFile(new ArrayList<>(key.keySet()), path);
        //        writeByteArrayListToFile(new ArrayList<>(key.values()), path);
        ArrayList<Byte> toWriteList = new ArrayList<>();
        key.entrySet().forEach(e -> {
            toWriteList.add(e.getKey());
            toWriteList.add((byte) 32); //Space
            toWriteList.add(e.getValue());
            toWriteList.add((byte) 10); //New line
        });

        //write the list to text file
        writeByteArrayListToFile(toWriteList, pathToWrite);
    }

    private static void writeByteArrayListToFile(ArrayList<Byte> bytes, String pathToWrite) {
        String toWrite;
        byte[] byteArray = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            byteArray[i] = bytes.get(i);
        }
        toWrite = new String(byteArray);
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(pathToWrite))) {
            writer.write(toWrite);
        } catch (IOException ex) {
            System.out.println(
                    "Error writing file "
            );
        }
    }

    //creates a list of byte array.
    //each byte array is in the size of blockSize
    private static ArrayList<byte[]> createByteList(byte[] text) {
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
