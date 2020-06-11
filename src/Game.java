import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class Game {
    public static void main(String[] args) throws IOException {
        if (!checkArguments(args))
            System.exit(1);
        String userMove = "1";
        Scanner reader = new Scanner(System.in);
        while (Integer.parseInt(userMove) != 0) {
            String compMove = generateCompMove(args.length);
            String key = generateKey();
            System.out.println("\n" + "HMAC: " + hmacDigest(compMove, key, "HmacSHA256"));
            userMenu(args);
            System.out.print("Enter your move: ");
            userMove = reader.next();
            Integer userChoice = Integer.parseInt(userMove);
            if (!isNumeric(userMove) || (userChoice > args.length) || (userChoice < 0)) {
                System.out.println("Wrong choice!");
                main(args);
            }
            if (userChoice == 0) {
                System.out.println("Your move: exit");
                System.exit(1);
            }
            System.out.println("Your move: " + args[userChoice - 1]);
            Integer compMov = Integer.parseInt(compMove);
            System.out.println("Computer move: " + args[compMov - 1]);
            System.out.println(compareMoves(userMove, compMove, args.length));
            System.out.println("HMAC key: " + key + "\n");
        }
    }

    public static boolean checkArguments(String[] args) {
        if ((args.length == 0) || (args.length < 3) || (args.length % 2 == 0)) {
            System.out.println("Arguments don't meet the requirements! Try again!");
            return false;
        }
        for (int i = 0; i < args.length; i++) {
            for (int j = i + 1; j < args.length; j++) {
                if (args[i].equals(args[j])) {
                    System.out.println("The arguments mustn't match. Try again!");
                    return false;
                }
            }
        }
        return true;
    }

    public static boolean isNumeric(String str) {
        if (str == null || str.isEmpty())
            return false;
        try {
            Integer.parseInt(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static void userMenu(String[] choice) {
        System.out.println("Available moves:");
        for (int i = 0; i < choice.length; i++) {
            System.out.println((i + 1) + " - " + choice[i]);
        }
        System.out.println("0 - exit");
    }

    public static String compareMoves(String userMove, String compMove, Integer length) {
        Integer userMov = Integer.parseInt(userMove);
        Integer compMov = Integer.parseInt(compMove);
        Integer mod = Math.abs(userMov - compMov);
        Integer len = (length - 1) / 2;
        if (mod == 0)
            return "Draw";
        else if ((mod > len && compMov < userMov) || (mod <= len && compMov > userMov))
            return "You win!";
        else if ((mod > len && compMov > userMov) || (mod <= len && compMov < userMov))
            return "You lose:(";
        return null;
    }

    public static String generateKey() {
        SecureRandom random;
        StringBuilder strBuilder = new StringBuilder();
        try {
            random = SecureRandom.getInstanceStrong();
            byte[] values = new byte[32];
            random.nextBytes(values);
            for (byte bt : values) {
                strBuilder.append(String.format("%02x", bt));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return strBuilder.toString();
    }

    public static String generateCompMove(int nums) {
        int move = (int) (Math.random() * nums) + 1;
        return String.valueOf(move);
    }

    public static String hmacDigest(String msg, String keyString, String algo) {
        String digest = null;
        try {
            SecretKeySpec key = new SecretKeySpec((keyString).getBytes("UTF-8"), algo);
            Mac mac = Mac.getInstance(algo);
            mac.init(key);
            byte[] bytes = mac.doFinal(msg.getBytes("ASCII"));
            StringBuffer hash = new StringBuffer();
            for (int i = 0; i < bytes.length; i++) {
                String hex = Integer.toHexString(0xFF & bytes[i]);
                if (hex.length() == 1) {
                    hash.append('0');
                }
                hash.append(hex);
            }
            digest = hash.toString();
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return digest;
    }
}