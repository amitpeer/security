package com.company;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner reader = new Scanner(System.in);
        String pathToKey = "C:\\Users\\windows\\Desktop\\secuerityExamples\\key_example.txt";
        String pathToText = "C:\\Users\\windows\\Desktop\\secuerityExamples\\plainMsg_example.txt";
        String pathToVector = "C:\\Users\\windows\\Desktop\\secuerityExamples\\IV_example.txt";
        String pathToEncryptionText = "C:\\Users\\windows\\Desktop\\secuerityExamples\\Encryption_example.txt";
        writeByteArrayListToFile(pathToEncryptionText , subCbc10Encryption(pathToText, pathToVector, pathToKey));
        //        String path = reader.next();
        //        Path fileLocation = Paths.get(path);
        //        try {
        //            byte[] data = Files.readAllBytes(fileLocation);
        //            String text = new String(data);
        //            System.out.print(text);
        //        } catch (IOException e) {
        //            e.printStackTrace();
        //        }
    }

    //Part A.a
    //change's - return arrayList
    private static ArrayList<byte[]> subCbc10Encryption(String textPath, String vectorPath, String keyPath) {
        byte[] text = readFileToByteArray(textPath);
        byte[] vector = readFileToByteArray(vectorPath);
        HashMap<Byte, Byte> key = readKeyToHashMap(keyPath);
        ArrayList<byte[]> textList = createByteList(text,10);
        ArrayList<byte[]> cipher = new ArrayList<>();

        //start CBC Encryption
        for (byte[] plainText : textList) {
            //do XOR for each byte with vector
            ArrayList<Byte> xorList = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                xorList.add((byte) (plainText[i] ^ vector[i]));
            }

            //do encryption function
            byte[] cipherText = new byte[10];
            int index = 0;
            for(byte b : xorList){
                cipherText[index] = key.getOrDefault(b, b);
                index++;
            }

            cipher.add(cipherText);

            //change vector to the recently encrypted text for the next iteration
            vector = cipherText;
        }
        return cipher;
    }

//    private static ArrayList<byte[]> subCbc10Decrtyption(String textPath, String vectorPath, String keyPath) {
//        byte[] text = readFileToByteArray(textPath);
//        byte[] vector = readFileToByteArray(vectorPath);
//        HashMap<Byte, Byte> key = readKeyToHashMap(keyPath);
//        ArrayList<byte[]> textList = createByteList(text,10);
//
//
//
//
//    }

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
    private static void writeByteArrayListToFile(String path,ArrayList<byte[]> byteArrayList)
    {
        String cipherString = "";
        for(byte[] plainText : byteArrayList){
            cipherString+= new String(plainText);
        }
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(path)))
        {
            writer.write(cipherString);
        }
        catch (IOException ex) {
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
}
