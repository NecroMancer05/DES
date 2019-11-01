/*
 * Bekircan DAL
 * bekircandal.amasya.05@gmail.com
 * DES implementation based this example on https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/
 */

package com.bekircan;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        var sc = new Scanner(System.in);

        System.out.print("Text: ");

        var text = sc.nextLine();

        var randomKey = GetRandomKey();
        var key = DES.GenerateKey(randomKey);

        System.out.println("Key: " + randomKey);

        var chipper = DES.Encrypt(key, text);
        System.out.println("Cipher text " + chipper);

        var plainText = DES.Decrypt(key, chipper);

        System.out.println("Plain text: " + plainText);
    }

    private static String GetRandomKey(){

        var random = new Random();
        var key = new StringBuffer();

        while(key.length() < 16)
            key.append(Integer.toHexString(random.nextInt()));

        return key.toString().substring(0, 16).toUpperCase();
    }

    public static class DES{

        //Hiding the constructor
        private DES(){

        }

        /**
         * Binary string to hex string
         * @param binary 4-bit split binary string
         * @return
         */
        public static String BinToHexString(String binary){

            var hexMap = new HashMap<String, String>();
            hexMap.put("0000", "0");
            hexMap.put("0001", "1");
            hexMap.put("0010", "2");
            hexMap.put("0011", "3");
            hexMap.put("0100", "4");
            hexMap.put("0101", "5");
            hexMap.put("0110", "6");
            hexMap.put("0111", "7");
            hexMap.put("1000", "8");
            hexMap.put("1001", "9");
            hexMap.put("1010", "A");
            hexMap.put("1011", "B");
            hexMap.put("1100", "C");
            hexMap.put("1101", "D");
            hexMap.put("1110", "E");
            hexMap.put("1111", "F");

            var hex = new StringBuilder();

            for (var i = 0; i < binary.length(); i += 4) {

                String index = String.valueOf(binary.charAt(i));

                index += binary.charAt(i + 1);
                index += binary.charAt(i + 2);
                index += binary.charAt(i + 3);

                hex.append(hexMap.get(index));
            }

            return hex.toString();
        }

        /**
         * Hex to 4-bit split binary string
         * @param hex
         * @return
         */
        public static String HexToBinString(String hex){

            var binaryMap = new HashMap<Character, String>();
            binaryMap.put('0', "0000");
            binaryMap.put('1', "0001");
            binaryMap.put('2', "0010");
            binaryMap.put('3', "0011");
            binaryMap.put('4', "0100");
            binaryMap.put('5', "0101");
            binaryMap.put('6', "0110");
            binaryMap.put('7', "0111");
            binaryMap.put('8', "1000");
            binaryMap.put('9', "1001");
            binaryMap.put('A', "1010");
            binaryMap.put('B', "1011");
            binaryMap.put('C', "1100");
            binaryMap.put('D', "1101");
            binaryMap.put('E', "1110");
            binaryMap.put('F', "1111");

            var binaryString = new StringBuilder();

            for (var i = 0; i < hex.length(); i++) {

                binaryString.append(binaryMap.get(hex.charAt(i)));
            }

            return binaryString.toString();
        }

        /**
         * Permutes the given string using the given table
         * @param string
         * @param table The permutation table
         * @param bitSize
         * @return
         */
        public static String Permute(String string, int[] table, int bitSize){

            if(bitSize < 0)
                throw new IllegalArgumentException("Bit size must > 0 : " + bitSize);

            if(bitSize > table.length)
                throw new IllegalArgumentException("Bit size bigger than table length! bit size:" + bitSize + " table length: " + table.length);

            var permuted = new StringBuilder();

            for (var i = 0; i < bitSize; i++) {

                permuted.append(string.charAt(table[i] - 1));
            }

            return permuted.toString();
        }

        /**
         * Performs xor operation between 2 binary strings
         * @param a
         * @param b
         * @return
         */
        public static String StringXOR(String a, String b){

            if(a.length() != b.length())
                throw new IllegalArgumentException("String lengths are not same! " + a.length() + " " + b.length());

            var result = new StringBuilder();

            for (var i = 0; i < a.length(); i++) {

                if(a.charAt(i) == b.charAt(i))
                    result.append("0");
                else
                    result.append("1");
            }

            return result.toString();
        }

        /**
         * Left shift operation for given string
         * @param string
         * @param shiftLength
         * @return
         */
        public static String LeftShift(String string, int shiftLength){

            var result = new StringBuilder();

            for (var i = 0; i < shiftLength; i++) {

                for (var j = 1; j < 28; j++) {

                    result.append(string.charAt(j));
                }

                result.append(string.charAt(0));
                string = result.toString();

                result = new StringBuilder();
            }

            return string;
        }

        /**
         * Generates 64-bit key form the given hex string
         * @param hexKey contains key information
         * @return
         */
        public static DESKey GenerateKey(String hexKey){

            if (hexKey == null || hexKey.isBlank())
                throw new IllegalArgumentException("Key null or blank!");

            hexKey = DESKey.GetValidKey(hexKey);

            var binaryKey = HexToBinString(hexKey);

            binaryKey = Permute(binaryKey, DESTables.keyPermutationTable, 56);

            var left = binaryKey.substring(0, 28);
            var right = binaryKey.substring(28, 56);

            var binaryKeys = new ArrayList<String>();

            //The 16 Rounds
            for (var i = 0; i < 16; i++) {

                left = LeftShift(left, DESTables.shiftTable[i]);
                right = LeftShift(right, DESTables.shiftTable[i]);

                var combineKey = left + right;

                var key = Permute(combineKey, DESTables.keyCompressionTable, 48);

                binaryKeys.add(key);
            }

            return new DESKey(binaryKeys);
        }

        public static String Encrypt(DESKey key, String data){

            return key.Encrypt(data);
        }

        public static String Decrypt(DESKey key, String cipher){

            return key.Decrypt(cipher);
        }
    }

    public static class DESTables{

        public static int[] initialPermutationTable = new int[]{
                58,50,42,34,26,18,10,2,
                60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6,
                64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,
                59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5,
                63,55,47,39,31,23,15,7 };

        public static int[] keyPermutationTable = new int[]{
                57,49,41,33,25,17,9,
                1,58,50,42,34,26,18,
                10,2,59,51,43,35,27,
                19,11,3,60,52,44,36,
                63,55,47,39,31,23,15,
                7,62,54,46,38,30,22,
                14,6,61,53,45,37,29,
                21,13,5,28,20,12,4 };

        public static int[] shiftTable = new int[]{
                1, 1, 2, 2,
                2, 2, 2, 2,
                1, 2, 2, 2,
                2, 2, 2, 1 };

        public static int[] keyCompressionTable = new int[]{
                14,17,11,24,1,5,
                3,28,15,6,21,10,
                23,19,12,4,26,8,
                16,7,27,20,13,2,
                41,52,31,37,47,55,
                30,40,51,45,33,48,
                44,49,39,56,34,53,
                46,42,50,36,29,32 };


        public static int[] DBoxTable= new int[] {
                32,1,2,3,4,5,4,5,
                6,7,8,9,8,9,10,11,
                12,13,12,13,14,15,16,17,
                16,17,18,19,20,21,20,21,
                22,23,24,25,24,25,26,27,
                28,29,28,29,30,31,32,1};

        public static int [][] SBox = new int[][]{
            {   14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
                0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
                4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
                15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
            },
            {    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
                 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
                 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
                 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
            },
            {
                10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
                13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
                13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
                1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
            },
            {
                7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
                13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
                10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
                3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
            },
            {
                2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
                14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
                4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
                11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
            },
            {
                12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
                10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
                9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
                4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
            },
            {
                4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
                13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
                1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
                6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
            },
            {
                13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
                 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
                 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
                 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
            }};

        public static int[] StraightPermutationTable = new int[]{
             16,7,20,21,
             29,12,28,17,
             1,15,23,26,
             5,18,31,10,
             2,8,24,14,
             32,27,3,9,
             19,13,30,6,
             22,11,4,25
        };

        public static int[] FinalPermutationTable = new int[]
        {    40,8,48,16,56,24,64,32,
                39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,
                37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,
                35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,
                33,1,41,9,49,17,57,25
        };
    }
}
