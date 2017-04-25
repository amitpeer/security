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
    private static HashMap<Byte, HashMap<Byte, Integer>> letterChangedCount = new HashMap<>();

    //member for part C:
    private static HashMap<Byte, Byte> key_long = new HashMap<>();

    public static void main(String[] args) {

        test();

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
        //        writeByteArrayInArrayListToFile(subCbcEncryption(textLong, vectorLong,
        //                                                         keyLong), pathToCaEncr);
        //
        //        String pathToCaCipher = "C:\\securityExamples\\examples_ascii\\PartC\\known_cipher.txt";
        //        writeByteArrayInArrayListToFile(subCbcDecryption(readFileToByteArray(pathToCaCipher), vectorLong,
        //                                                         keyLong), pathToCAdecry);

        String pathToCBcipher = "C:\\securityExamples\\examples_ascii\\PartC2\\unknown_cipher.txt";
        String pathToCBVector = "C:\\securityExamples\\examples_ascii\\PartC2\\IV_long.txt";
        String pathToCBcipherMessage = "C:\\securityExamples\\examples_ascii\\PartC2\\known_cipher.txt";
        String pathToCBplainTextMessage = "C:\\securityExamples\\examples_ascii\\PartC2\\known_plain_long.txt";
        String pathToKeyLong2 = "C:\\securityExamples\\examples_ascii\\PartC2\\key_long.txt";
        byte[] vectorLong2 = readFileToByteArray(pathToCBVector);
        byte[] cipher2 = readFileToByteArray(pathToCBcipher);
        byte[] plainTextMessage = readFileToByteArray(pathToCBplainTextMessage);
        byte[] cipherMessage = readFileToByteArray(pathToCBcipherMessage);
        HashMap<Byte, Byte> keyLong2 = readKeyToHashMap(pathToKeyLong2);

        knownPlainTextAttack(cipher2, vectorLong2, cipherMessage, plainTextMessage);
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

        ///for debag
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

    //Part C
    private static void knownPlainTextAttack(byte[] cipher, byte[] vector, byte[] cipherMessage, byte[] plainTextMessage) {

        //Make a partial key out of the cipher message + plainText message using XOR
        byte plainTextAfterXor;
        for (int i = 0; i < plainTextMessage.length; i++) {
            plainTextAfterXor = (byte) (plainTextMessage[i] ^ vector[i]);
            if ((plainTextAfterXor >= 65 && plainTextAfterXor <= 90) || (plainTextAfterXor >= 97 && plainTextAfterXor <= 122)) {
                key_long.put(plainTextAfterXor, cipherMessage[i]);
            }
        }

        //for testing
        writeKeyToFile(key_long, "C:\\securityExamples\\examples_ascii\\PartC2\\partialKey_key.txt");

        //divide cipher
        ArrayList<byte[]> cipherByBlocks = divideToArrayListOfBytes(cipher);

        //load words dictionary
        loadDictionaryToMemory();
        //if the key is smaller than 42, we haven't found all of the key yet
        //else, the key is ready to be written
        if (key_long.size() < 52) {
            //decrypt cipher message and separate into words
            //find words that only 1 letter has not been changed in encryption algorithm
            //use all other letters to check for real words instead
            ArrayList<byte[]> plainText = subCbcDecryption(cipher, vector, key_long);
            writeByteArrayInArrayListToFile(plainText,"C:\\securityExamples\\examples_ascii\\PartC2\\patial_decrypted_Text.txt");
            int blockIndex = 0;
            int indexOfChange;
            int indexInBlock;
            byte[] plainTextBlock;

            while (key_long.size() < 52 && blockIndex < cipherByBlocks.size()) {
                indexInBlock = 0;
                plainTextBlock = plainText.get(blockIndex);
                ArrayList<Byte> word = new ArrayList<>();
                for (byte b : plainTextBlock) {
                    if (b >= 65) {
                        word.add(b);
                    } else if (word.size()>1) {
                        byte[] cipherBlock = cipherByBlocks.get(blockIndex);
                        indexOfChange = indexOfChangeIfOnlyOne(word, vector, cipherBlock,indexInBlock);
                        if (indexOfChange != -1) {
                            tryFindCorrectWord(word, indexOfChange, indexInBlock, vector, cipherBlock);
                        }
                        word = new ArrayList<>();
                    }
                    indexInBlock++;
                }
                //before go to the next block:
                // take the maximum of z from each X->(y,z) and put in the final key dictionary
                putBestMatch();

                //change vector for the next block
                ArrayList<byte[]> vectorList = subCbcEncryption(plainText.get(blockIndex), vector, key_long);
                for (int i = 0; i < vector.length; i++) {
                    vector[i] = vectorList.get(0)[i];
                }
                blockIndex++;
            }
        }
        writeKeyToFile(key_long, "C:\\securityExamples\\examples_ascii\\PartC2\\my_key.txt");
    }

    private static void putBestMatch() {
        //iterate on all letters in potential keys Map
        byte valueForFinalKey = -1;
        for (Map.Entry<Byte, HashMap<Byte, Integer>> entry : letterChangedCount.entrySet()) {
            byte keyLetter = entry.getKey();
            HashMap<Byte, Integer> keyLetterMap = entry.getValue();
            int maximum = 0;
            //for wach letter check the best key
            for (Map.Entry<Byte, Integer> entryInMap : keyLetterMap.entrySet()) {
                int keyletterValue = entryInMap.getValue();
                if (maximum < keyletterValue) {
                    valueForFinalKey = entryInMap.getKey();
                    maximum = keyletterValue;
                }
            }
            if (valueForFinalKey != -1)
                key_long.put(keyLetter, valueForFinalKey);
        }

    }


    //dividing byte[] to arrayList of byte[]
    //when all the byte[] elements in size of BlockSize
    private static ArrayList<byte[]> divideToArrayListOfBytes(byte[] byteArray) {
        ArrayList<byte[]> divided = new ArrayList<>();
        byte[] dividedElement = new byte[blockSize];
        int indexing = 0;
        for (byte b : byteArray) {
            if (indexing < blockSize) {
                dividedElement[indexing] = b;
                indexing++;
            } else {
                divided.add(dividedElement);
                dividedElement = new byte[blockSize];
                indexing = 0;
            }
        }
        return divided;
    }

    private static void tryFindCorrectWord(ArrayList<Byte> word, int indexOfChange,
                                           int indexInBlock, byte[] cipherBlock, byte[] vector) {
        for (int i = 65; i <= 122; i++) {
            if (i >= 65 && i <= 90 || i >= 97 && i <= 122) { //between a-z or A-Z
                byte xor = (byte) (i ^ vector[indexInBlock]);   //the xor is The key
                if (!key_long.containsKey((byte) i)) { //change only letters that not in the dictionary
                    ArrayList<Byte> newWord = new ArrayList<>(word);
                    newWord.set(indexOfChange, xor);  //we check for word in dictionary so must xor it for the regular word
                    if (WORDS.contains(newWord)) {
                        //now put in the dictionary the letter
                        byte cipherLetter = cipherBlock[indexInBlock-indexOfChange]; //the letter in the cipher is the value. X->Y (in cipher is the Y)
                        putInDictionaryLetter(xor, cipherLetter);

                    }
                }
            }
        }
    }

    private static void putInDictionaryLetter(byte key, byte cipherLetter) {
        int valueOfLetterInDic = ((HashMap<Byte, Integer>) letterChangedCount.values()).get(cipherLetter);
        HashMap<Byte, Integer> apply = new HashMap<>();
        if (valueOfLetterInDic > 0) // if the letter exist
        {
            apply.put(cipherLetter, valueOfLetterInDic + 1);
        } else {
            apply.put(cipherLetter, 1);
        }
        letterChangedCount.put(key, apply);
    }

    private static int indexOfChangeIfOnlyOne(ArrayList<Byte> word, byte[] vector, byte[] cipherBlock,
                                              int indexInBlock) {
        int counter = 0;
        int vectorIndex = indexInBlock - word.size();
        int wordIndex = 0;
        for (int i = 0; i < word.size(); i++) {
            byte letter = cipherBlock[vectorIndex];
            if (letter==((byte) (word.get(i) ^ vector[vectorIndex])) &&
                    (key_long.get(letter)!=null && key_long.get(letter)!=letter)) { //only if the letter is the same in the cipher (didn'y decrypted) and do no
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

    // PART C - OLD

//    private static void knownPlainTextAttack(byte[] cipher, byte[] vector, byte[] cipherMessage, byte[] plainTextMessage) {
//        byte plainTextAfterXor;
//        for (int i = 0; i < plainTextMessage.length; i++) {
//            plainTextAfterXor = (byte) (plainTextMessage[i] ^ vector[i]);
//            if ((plainTextAfterXor >= 65 && plainTextAfterXor <= 90) || plainTextAfterXor >= 97 && plainTextAfterXor <= 122) {
//                key_long.put(plainTextAfterXor, cipherMessage[i]);
//            }
//        }
//
//        ArrayList<byte[]> partialText = subCbcDecryption(cipher, vector, key_long);
//        ArrayList<Byte> word = new ArrayList<>();
//        int blockIndex = 0;
//        int attackIndexVector = 0;
//        int attackIndexCipher = 0;
//        while (key_long.size() < 52 && blockIndex < partialText.size())  //maybe need more condition on length
//        {
//            attackIndexVector = 0;
//            for (byte b : partialText.get(blockIndex)) {
//                byte cipherByte = cipher[attackIndexCipher];
//                if ((cipherByte >= 65 && cipherByte <= 90) || (cipherByte >= 97 && cipherByte <= 122)) {
//                    insertKeyTuple(b, cipher[attackIndexCipher], vector[attackIndexVector]);
//                    blockSize = 8128;
//                }
//                attackIndexVector++;
//                attackIndexCipher++;
//            }
//            //change vector for the next block
//            ArrayList<byte[]> vectorList = subCbcEncryption(partialText.get(blockIndex), vector, key_long);
//            for (int i = 0; i < vector.length; i++) {
//                vector[i] = vectorList.get(0)[i];
//            }
//
//            //next block
//            blockIndex++;
//        }
//        writeKeyToFile(key_long, "C:\\securityExamples\\examples_ascii\\PartC2\\my_key.txt");
//    }
//
//
//    private static void insertKeyTuple(byte byteToCheck, byte byteCipher, byte byteVector) {
//        byte[] singleByteVec = {byteVector};
//        byte[] singleByteToEncrypt = {byteToCheck};
//        for (int i = 65; i <= 122; i++) {
//            if ((i >= 65 && i <= 90) || (i >= 97 && i <= 122)) { //between a-z or A-Z
//                if (!key_long.containsKey((byte) i)) {
//                    HashMap<Byte, Byte> keyAsSingleByte = new HashMap<>();
//                    keyAsSingleByte.put((byte) i, byteCipher);
//                    blockSize = 1;
//                    ArrayList<byte[]> encrypted = subCbcEncryption(singleByteToEncrypt, singleByteVec, keyAsSingleByte);
//                    if (encrypted.get(0)[0] == byteCipher) {
//                        key_long.putAll(keyAsSingleByte);
//                        return;
//                    }
//                }
//            }
//        }
//    }
}