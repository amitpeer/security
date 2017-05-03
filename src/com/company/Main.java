package com.company;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
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
    private static HashMap<Byte, HashMap<Byte, Integer>> letterChangedCount = new HashMap<>();

    //member for part C:
    private static HashMap<Byte, Byte> key_long = new HashMap<>();
    private static HashMap<Character, Character> key_longAsChar = new HashMap<>();
    private static HashMap<Character, Character> my_key_long = new HashMap<>();
    private static int countKeyChange;

    private static HashSet<Character> allLettersSet = new HashSet<>();
    private static HashSet<Character> allLTheABC = new HashSet<>();
    private static ArrayList<Character> firstFoundWord = new ArrayList<>();

    public static void main(String[] args) {

        String algorithm;
        String action;
        String pathToWrite;
        String pathToknownPlainText;
        String pathToknownCipher;
        String pathToKey;
        HashMap<Byte, Byte> key;
        byte[] text;
        byte[] vector;
        byte[] knownPlainText;
        byte[] knownCipher;

        //handle arguments
        try {
            List<String> argsList = Arrays.asList(args);
            algorithm = argsList.get(argsList.indexOf("-a") + 1);
            action = argsList.get(argsList.indexOf("-c") + 1);
            String pathToText = argsList.get(argsList.indexOf("-t") + 1);
            pathToKey = argsList.get(argsList.indexOf("-k") + 1);
            String pathToVector = argsList.get(argsList.indexOf("-v") + 1);
            pathToWrite = argsList.get(argsList.indexOf("-o") + 1);
            pathToknownPlainText = argsList.get(argsList.indexOf("-kp") + 1);
            pathToknownCipher = argsList.get(argsList.indexOf("-kc") + 1);

            text = readFileToByteArray(pathToText);
            vector = readFileToByteArray(pathToVector);
        } catch (Exception e) {
            System.out.print("Bad input");
            return;
        }

        //set the block size according to algorithm
        if (algorithm.equals("sub_cbc_10")) {
            blockSize = 10;
        } else if (algorithm.equals("sub_cbc_52")) {
            blockSize = 8128;
        }

        try {
            if (action.equals("encryption")) {
                key = readKeyToHashMap(pathToKey);
                writeByteArrayInArrayListToFile(subCbcEncryption(text, vector, key), pathToWrite);
            } else if (action.equals("decryption")) {
                key = readKeyToHashMap(pathToKey);
                writeByteArrayInArrayListToFile(subCbcDecryption(text, vector, key), pathToWrite);
            }

            if (action.equals("attack") && algorithm.equals("sub_cbc_10")) {
                cipherTextOnlyAttack(text, vector, pathToWrite, "abcdefgh");
            } else if (action.equals("attack") && algorithm.equals("sub_cbc_52")) {
                knownPlainText = readFileToByteArray(pathToknownPlainText);
                knownCipher = readFileToByteArray(pathToknownCipher);
                knownPlainTextAttack(text, vector, knownCipher, knownPlainText, pathToWrite);
            }
        } catch (Exception e) {
            System.out.println("Error occurred. Please check input and try again");
            System.out.println(e.getMessage());
        }
    }

    public static byte[] toByteArrayUsingJava(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int reads = is.read();
        while (reads != -1) {
            baos.write(reads);
            reads = is.read();
        }
        return baos.toByteArray();
    }

    private static void testOnAnotherText(String pathToTextx) {
        byte[] vector = readFileToByteArray("C:\\securityExamples\\examples_ascii\\PartC2\\IV_long.txt");
        byte[] text = readFileToByteArray(pathToTextx);
        HashMap<Byte, Byte> key = readKeyToHashMap("C:\\securityExamples\\examples_ascii\\examples\\key_Long_Example.txt");
        String pathForCipher = "C:\\securityExamples\\Corpus\\cipher_example.txt";
        ArrayList<byte[]> encryption = subCbcEncryption(text, vector, key);
        writeByteArrayInArrayListToFile(encryption, pathForCipher);

        //make known cipherPacket and known text packet:
        byte[] knownPlainText = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            knownPlainText[i] = text[i];
        }
        byte[] knownCiper = encryption.get(0);
        byte[] cipher = readFileToByteArray(pathForCipher);
        knownPlainTextAttack(cipher, vector, knownCiper, knownPlainText, "C:\\securityExamples\\Corpus\\my_Key.txt");
    }

    private static void testPartA() {

    }

    private static void testPartB() {
        //part b testing
        String pathToKey = "C:\\securityExamples\\examples_ascii\\PartB\\key_short.txt";
        String pathToText = "C:\\securityExamples\\plainMsg_example.txt";

        String pathToEncryptionText = "C:\\securityExamples\\additional_examples\\PartB\\my_cipher.txt";
        String pathToDecryptionText = "C:\\securityExamples\\my_text.txt";
        String pathToCipher = "C:\\securityExamples\\examples_ascii\\PartB\\cipher.txt";
        String pathToVectorAttack = "C:\\securityExamples\\examples_ascii\\PartB\\IV_short.txt";
        String pathToweiteKey = "C:\\securityExamples\\examples_ascii\\PartB\\my_Key.txt";
        //part a testing
        HashMap<Byte, Byte> key = readKeyToHashMap(pathToKey);
        byte[] vector = readFileToByteArray(pathToVectorAttack);
        byte[] cipher = readFileToByteArray(pathToCipher);
        blockSize = 10;
        cipherTextOnlyAttack(cipher, vector, pathToweiteKey, "abcdefgh");

        writeByteArrayInArrayListToFile(subCbcDecryption(cipher, vector, bestKey), pathToDecryptionText);
    }

    private static void testPartC() {

        //part c testing
        String pathToCBcipher = "C:\\securityExamples\\examples_ascii\\PartC2\\unknown_cipher.txt";
        String pathToCBVector = "C:\\securityExamples\\examples_ascii\\PartC2\\IV_long.txt";
        String pathToCBcipherMessage = "C:\\securityExamples\\examples_ascii\\PartC2\\known_cipher.txt";
        String pathToCBplainTextMessage = "C:\\securityExamples\\examples_ascii\\PartC2\\known_plain_long.txt";
        String pathToWriteKeyLongText = "C:\\securityExamples\\examples_ascii\\PartC2\\my_TextCheck.txt";
        byte[] vectorLong2 = readFileToByteArray(pathToCBVector);
        byte[] cipher2 = readFileToByteArray(pathToCBcipher);
        byte[] plainTextMessage = readFileToByteArray(pathToCBplainTextMessage);
        byte[] cipherMessage = readFileToByteArray(pathToCBcipherMessage);
        blockSize = 8128;
        knownPlainTextAttack(cipher2, vectorLong2, cipherMessage, plainTextMessage, "\\src\\key_long.txt");
        writeByteArrayInArrayListToFile(subCbcDecryption(cipher2, vectorLong2, key_long), pathToWriteKeyLongText);
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
    private static void cipherTextOnlyAttack(byte[] cipher, byte[] vector, String pathToWrite, String missingKeys) {
        loadDictionaryToMemory();

        System.out.println("Trying to find key..");

        char[] keyValue = missingKeys.toCharArray();
        HashMap<Byte, Byte> potentialKeyMap = null;
        Set<String> allKeysSet = generatePerm(missingKeys);
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
            for (int i = 0; i <= 2250; i++) {
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

        //Put all words in one array list
        // (because the arrays in text are in the size of blockSize each)
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

        //check if the words are in english using the English dictionary loaded to memory
        //long numberOfEnglishWords = words.stream().filter(WORDS::contains).count();
        int numberOfEnglishWords = 0;
        for (ArrayList<Byte> wordInWords : words) {

            Stream<Byte> capitaleCheck = wordInWords.stream().map(b -> (byte) (b + (byte) 32));
            ArrayList<Byte> capitaleCheckList = new ArrayList<>();
            ArrayList<Byte> captialFirstOnly = new ArrayList<>(wordInWords);
            capitaleCheck.parallel().forEachOrdered(capitaleCheckList::add);

            if (WORDS.contains(wordInWords) || WORDS.contains(capitaleCheckList) || WORDS.contains(captialFirstOnly))
                numberOfEnglishWords++;
        }

        if (numberOfEnglishWords > maximumWordsFromKey) {
            bestKey = new HashMap<>(potentialKey);
            maximumWordsFromKey = numberOfEnglishWords;
        }
        return isCorrectKey;
    }

    //Part C
    private static void knownPlainTextAttack(byte[] cipher, byte[] vector, byte[] cipherMessage, byte[] plainTextMessage,
                                             String pathToWriteKey) {

        //Make a partial key out of the cipher message + plainText message using XOR
        byte plainTextAfterXor;
        byte[] initialVector = Arrays.copyOf(vector, vector.length);
        //fill letter set
        fillLetterSet();
        for (int i = 0; i < plainTextMessage.length; i++) {
            plainTextAfterXor = (byte) (plainTextMessage[i] ^ vector[i]);
            char plainTextAsChar = (char) plainTextAfterXor;
            if (allLettersSet.contains(plainTextAsChar)) {
                key_longAsChar.put(plainTextAsChar, (char) cipherMessage[i]);
                key_long.put(plainTextAfterXor, cipherMessage[i]);
                allLettersSet.remove(plainTextAsChar);
            }
        }

        //divide cipher
        ArrayList<byte[]> cipherByBlocks = divideToArrayListOfBytes(cipher);

        //load words dictionary
        loadDictionaryToMemory();

        int blockIndex = 0;
        int indexOfChange;
        int indexInBlock;
        byte[] plainTextBlock;

        while (key_long.size() < 52 && blockIndex < cipherByBlocks.size()) {
            indexInBlock = 0;
            byte[] cipherBlock = cipherByBlocks.get(blockIndex);
            ArrayList<byte[]> plainText = subCbcDecryption(cipherBlock, vector, key_long);
            plainTextBlock = plainText.get(0);
            ArrayList<Character> word = new ArrayList<>();
            char[] plainTextAsCharArr = byteArrToCharArr(plainTextBlock);
            for (char ch : plainTextAsCharArr) {
                if (ch != ' ' && ch != '\n' && ch != '\r') {
                    word.add(ch);
                } else {
                    indexOfChange = indexOfChangeIfOnlyOne(word, vector, cipherBlock, indexInBlock);
                    if (indexOfChange != -1) {
                        tryFindCorrectWord(word, indexOfChange, indexInBlock, cipherBlock, vector);
                    }
                    word = new ArrayList<>();
                }
                indexInBlock++;
            }

            //change vector for the next block
            vector = Arrays.copyOf(cipherBlock, cipherBlock.length);
            blockIndex++;
        }

        //if only 8 letters are missing in the key, use brute force
        if (allLettersSet.size() < 9 && !allLettersSet.isEmpty()) {
            String missingKeys = hashSetToArray(allLettersSet);
            cipherTextOnlyAttack(cipher, initialVector, pathToWriteKey, missingKeys);
        }
        writeKeyToFile(key_long, pathToWriteKey);
    }

    private static void tryFindCorrectWord(ArrayList<Character> word, int indexOfChange,
                                           int indexInBlock, byte[] cipherBlock, byte[] vector) {
        int countMatchLetters = 0;
        char letterMatch = ' ';
        byte cipherLetter = -1;
        ArrayList<Character> newWord;
        for (char ch : allLTheABC) {
            byte xor = (byte) (ch ^ vector[indexInBlock - word.size() + indexOfChange]);  //the xor is The key
            newWord = new ArrayList<>(word);
            newWord.set(indexOfChange, (char) xor);  //we check for word in dictionary so must xor it for the regular word
            //check if the word with the letter change is in english
            if (WORDS.contains(charToByteArrys(newWord)) && indexOfChange != 0) {
                //put in the dictionary the letter
                cipherLetter = cipherBlock[indexInBlock - word.size() + indexOfChange]; //the letter in the cipher is the value. X->Y (in cipher is the Y)
                letterMatch = ch;
                countMatchLetters++;
                firstFoundWord = newWord;
            }
        }
        //only if there is one letter that match to the change - it is for sure in the key.
        if (countMatchLetters == 1 && !key_longAsChar.containsKey(letterMatch)) {
            key_long.put((byte) (letterMatch + 0), cipherLetter);
            key_longAsChar.put(letterMatch, (char) cipherLetter);
            my_key_long.put(letterMatch, (char) cipherLetter);
            allLettersSet.remove(letterMatch);
        }
    }

    private static ArrayList<byte[]> divideToArrayListOfBytes(byte[] byteArray) {
        ArrayList<byte[]> divided = new ArrayList<>();
        byte[] dividedElement = new byte[blockSize];
        int counter = 0;
        for (int i = 0; i < byteArray.length / blockSize; i++) {
            for (int j = 0; j < blockSize; j++) {
                dividedElement[j] = byteArray[counter];
                counter++;
            }
            divided.add(dividedElement);
            dividedElement = new byte[blockSize];
        }
        return divided;
    }

    private static char[] byteArrToCharArr(byte[] byteArr) {
        char[] toreturn = new char[byteArr.length];
        int index = 0;
        for (byte b : byteArr) {
            toreturn[index] = (char) byteArr[index];
            index++;
        }

        return toreturn;
    }

    private static void fillLetterSet() {
        String allLetter = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (char c : allLetter.toCharArray()) {
            allLettersSet.add(c);
        }
        for (char c : allLetter.toCharArray()) {
            allLTheABC.add(c);
        }
    }

    private static ArrayList<Byte> charToByteArrys(ArrayList<Character> arrayListChar) {
        ArrayList<Byte> toReturn = new ArrayList<>();
        for (char ch : arrayListChar) {
            toReturn.add((byte) ch);
        }
        return toReturn;
    }

    private static int indexOfChangeIfOnlyOne(ArrayList<Character> word, byte[] vector, byte[] cipherBlock,
                                              int indexInBlock) {
        int counter = 0;
        int vectorIndex = indexInBlock - word.size();
        int wordIndex = 0;
        for (int i = 0; i < word.size(); i++) {
            char letter = (char) cipherBlock[vectorIndex];
            char xored = (char) (word.get(i) ^ vector[vectorIndex]);
            if (letter == xored && (allLettersSet.contains(xored) || key_longAsChar.containsKey(xored))) { //only if the letter is the same in the cipher (didn'y decrypted) and do no
                //have the same key and value in the dictionary (for example O->0)
                counter++;
                wordIndex = i;
            }
            vectorIndex++;
        }
        if (counter == 1)
            return wordIndex;
        return -1;
    }

    private static void loadDictionaryToMemory() {
        //load english dictionary to byte array
        String pathToDic = new File("").getAbsolutePath() + "\\dictionary.txt";

        byte[] words = null;
        try {
            words = readFileFromJar();
        } catch (IOException e) {
            System.out.println("Error reading dictionary");
            e.printStackTrace();
        }

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

    private static byte[] readFileFromJar() throws IOException {
        URL url = Main.class.getResource("/dictionary.txt");
        InputStream stream = null;
        try {
            stream = url.openStream();
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] words = toByteArrayUsingJava(stream);

        return words;
    }

    //write key to file
    private static void writeKeyToFile(HashMap<Byte, Byte> key, String pathToWrite) {
        System.out.println("Writing key to " + pathToWrite);
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

    private static String hashSetToArray(HashSet<Character> allLettersSet) {
        String ans = "";
        for (Character s : allLettersSet){
            ans += s;
        }
        return ans;
    }
}