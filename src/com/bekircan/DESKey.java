package com.bekircan;

import com.bekircan.Main.DESTables;

import java.util.ArrayList;

import static com.bekircan.Main.DES.*;

public class DESKey {

    private ArrayList<String> Keys;

    private int splitIndex;

    DESKey(ArrayList<String> keys) {
        this.Keys = keys;
    }

    static String GetValidKey(String key){

        if(key.length() == 16)
            return key;
        else if(key.length() > 16)
            return key.substring(0, 16);
        else{

            var need = 16 - key.length();

            var keyBuilder = new StringBuilder(key);

            for (var i = 0; i < need; i++) {

                keyBuilder.append("0");
            }
            key = keyBuilder.toString();

            return key;
        }
    }

    static String[] GetValidString(String data){

        if(data.length() == 64)
            return new String[]{ data };
        else if(data.length() < 64){

            var offset = 64 - data.length();

            var dataBuilder = new StringBuilder(data);

            for (var i = 0; i < offset; i++) {

                dataBuilder.append("0");
            }

            return new String[] { dataBuilder.toString() };
        }

        int length = (data.length() / 64) + 1;
//        var validData = new String[length];
        var validData = new ArrayList<String>();

        for (var i = 0; i < length; i++) {

            if(i + 1 == length){

                var offset = 64 * (i + 1) - data.length();

                if(offset == 0)
                    continue;

                var lastPart = new StringBuilder(data.substring(64 * i));

                for(var j = 0; j < offset; j++){

                    lastPart.append("0");
                }

//                validData[i] = lastPart.toString();
                validData.add(lastPart.toString());
            }
            else{
//                validData[i] = data.substring(i * 64, (i + 1) * 64);
                validData.add(data.substring(i * 64, (i + 1) * 64));
            }
        }

        var arr = new String[validData.size()];
        for (int i = 0; i < validData.size(); i++) {
            arr[i] = validData.get(i);
        }

        return arr;
    }

    static int GetLastCharIndex(String data){

        if(data.length() <= 64)
            return data.length();

        int length = (data.length() / 64) + 1;
        var validData = new ArrayList<String>();

        for (var i = 0; i < length; i++) {

            if(i + 1 == length){

                var offset = 64 * (i + 1) - data.length();

                if(offset == 0)
                    continue;

                return (validData.size() * 64) + 64 - offset;
            }
            else{
//                validData[i] = data.substring(i * 64, (i + 1) * 64);
                validData.add(data.substring(i * 64, (i + 1) * 64));
            }
        }

        return validData.size() * 64;
    }

    static byte[] HexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    static String StringToBinary(String text){

        byte[] bytes = text.getBytes();
        StringBuilder binary = new StringBuilder();
        for (byte b : bytes)
        {
            int val = b;
            for (int i = 0; i < 8; i++)
            {
                binary.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }
        }

        return binary.toString();
    }

    String Encrypt(String text){

        if(text == null)
            throw new NullPointerException("Given string is null!");

        var binText= StringToBinary(text);
        var dataArray = GetValidString(binText);
        splitIndex = GetLastCharIndex(binText);

        for (var i = 0; i < dataArray.length; i++) {

            var currentData = Permute(dataArray[i], DESTables.initialPermutationTable, 64);

            var left = currentData.substring(0, 32);
            var right = currentData.substring(32);

            for (var j = 0; j < 16; j++) {

                var rightExpanded = Permute(right, DESTables.DBoxTable, 48);

                var xor = StringXOR(Keys.get(i), rightExpanded);

                var sBoxed = new StringBuilder();

                for (var k = 0; k < 8; k++) {

                    int row = Integer.parseInt("" + xor.charAt(k * 6) + xor.charAt((k * 6) + 5), 2);
                    int col = Integer.parseInt("" + xor.charAt((k * 6) + 1) + xor.charAt((k * 6) + 2) + xor.charAt((k * 6) + 3) + xor.charAt((k * 6) + 4), 2);

                    int val = DESTables.SBox[k][(row * 16) + col];

                    sBoxed.append(HexToBinString(Integer.toHexString(val).toUpperCase()));
                }

                var afterSBox = sBoxed.toString();

                afterSBox = Permute(afterSBox, DESTables.StraightPermutationTable, 32);

                left = StringXOR(afterSBox, left);

                if(j != 15){

                    var temp = left;
                    left = right;
                    right = temp;
                }

//                System.out.print("left " + BinToHexString(left));
//                System.out.println(" right " + BinToHexString(right));
            }

            var combine = left + right;

            dataArray[i] = BinToHexString(Permute(combine, DESTables.FinalPermutationTable, 64));
        }

        var cipherText = new StringBuilder();

        for (int i = 0; i < dataArray.length; i++) {

            cipherText.append(dataArray[i]);
        }

        return cipherText.toString();
    }

    String Decrypt(String text){

        if(text == null)
            throw new NullPointerException("Given string is null!");

        var binText = HexToBinString(text);
        var dataArray = GetValidString(binText);

        for (var i = 0; i < dataArray.length; i++) {

            var currentData = Permute(dataArray[i], DESTables.initialPermutationTable, 64);

            var left = currentData.substring(0, 32);
            var right = currentData.substring(32);

            for (var j = 0; j < 16; j++) {

                var rightExpanded = Permute(right, DESTables.DBoxTable, 48);

                var xor = StringXOR(Keys.get(i), rightExpanded);

                var sBoxed = new StringBuilder();

                for (var k = 0; k < 8; k++) {

                    int row = Integer.parseInt("" + xor.charAt(k * 6) + xor.charAt((k * 6) + 5), 2);
                    int col = Integer.parseInt("" + xor.charAt((k * 6) + 1) + xor.charAt((k * 6) + 2) + xor.charAt((k * 6) + 3) + xor.charAt((k * 6) + 4), 2);

                    int val = DESTables.SBox[k][(row * 16) + col];

                    sBoxed.append(HexToBinString(Integer.toHexString(val).toUpperCase()));
                }

                var afterSBox = sBoxed.toString();

                afterSBox = Permute(afterSBox, DESTables.StraightPermutationTable, 32);

                left = StringXOR(afterSBox, left);

                if(j != 15){

                    var temp = left;
                    left = right;
                    right = temp;
                }

//                System.out.print("left " + BinToHexString(left));
//                System.out.println(" right " + BinToHexString(right));
            }

            var combine = left + right;

//            dataArray[i] = BinToHexString(Permute(combine, DESTables.FinalPermutationTable, 64));
            dataArray[i] = Permute(combine, DESTables.FinalPermutationTable, 64);
        }

        var cipherText = new StringBuilder();

        for (int i = 0; i < dataArray.length; i++) {

            cipherText.append(dataArray[i]);
        }

        return new String(HexStringToByteArray(BinToHexString(cipherText.toString().substring(0, splitIndex))));
    }
}