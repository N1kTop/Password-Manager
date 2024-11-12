import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.*;

public class Main {

    private static String accountUsername = null;
    private static String accountPassword = null;
    private static List<List<String>> records = new ArrayList<>();
    private static boolean CSVfileRequiresRewriting = false;
    private static final String SPECIAL_CHARACTERS = "/?#@-=_+!^";
    private static final String EXTRA_CHARACTERS = "(){}[]|`¬~£$&*%<>.,:;\"'\\";
    private static final String LOWERCASE = "abcdefghigklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIGKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";

    private static List<String> wordsDict;

    public static void main(String[] args) {
        loadDictionary();
        mainMenu();

    }

    private static void mainMenu() {

        while (true) {
            System.out.println("""
                    (1) Log-in
                    (2) Sign-up
                    (3) About
                    (4) Exit
                    """);
            int choice = inputInt("Enter number: ", 1, 4);

            switch (choice) {
                case 1 -> {logIn();}
                case 2 -> {signUp();}
                case 3 -> {printAboutPage();}
                case 4 -> {return;}
            }
        }
    }

    private static void accountMenu() {
        int choice = 0;
        while (choice != 5) {
            System.out.println("""
                    (1) Manage Passwords
                    (2) Add New Password
                    (3) Generate Password
                    (4) Account Settings
                    (5) Log-out
                    """);
            choice = inputInt("Enter number: ", 1, 5);

            switch (choice) {
                case 1 -> managePasswordsMenu();
                case 2 -> addNewPassword();
                case 3 -> passwordGenMenu();
                case 4 -> settingsMenu();
                case 5 -> logOut();
            }
        }
    }

    private static void logOut() {
        if (CSVfileRequiresRewriting) {
            writeRecordsToCSV(accountUsername + ".csv");
        }
        accountUsername = null;
        accountPassword = null;
    }

    private static void managePasswordsMenu() {
        while (true) {
            printAllAccounts();
            int choice = inputInt("Enter 0 to return or type password index to manage service: ");

            if (choice <= 0 || choice >= records.size()) return;

            menageServicePassword(choice);

        }
    }

    private static void addNewPassword() {
        // finish
    }

    private static void menageServicePassword(int index) {
        System.out.println(records.get(index).get(0));
        System.out.println(records.get(index).get(1));
        System.out.println(records.get(index).get(3));

        System.out.println("""
                
                (1) Copy password
                (2) Change Password
                (3) Change Username
                (4) Remove Service
                (5) Back
                """);

        int choice = inputInt("Enter number: ", 1, 4);

        switch (choice) {
            case 1 -> copyToClipboard("finish");
            case 2 -> updatePassword(index);
            case 3 -> {
                records.get(index).set(1, input("\nNew Username: "));
                CSVfileRequiresRewriting = true;
            }
            case 4 -> {
                records.remove(index);
                CSVfileRequiresRewriting = true;
            }
        }
    }

    private static void updatePassword(int index) {
        String newPasswordString = input("\nNew Password: ");
        CSVfileRequiresRewriting = true;
        // finish
        records.get(index).set(2, newPasswordString);
    }

    private static void printAllAccounts() {
        System.out.print("\n");
        for (int i = 1; i < records.size(); i++) {
            System.out.println((i) + " " + records.get(i).get(0) + " " + records.get(i).get(1));
        }
        System.out.print("\n");
    }

    private static String getRecordsSalt(int index) {
        return records.get(index).get(3);
    }

    private static boolean loadRecords(String filename) {
        records = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                records.add(Arrays.asList(values));
            }
            return true;
        } catch (IOException e) {
            System.out.println("\nThe file for this username was not found\n");
            return false;
        }
    }

    private static void writeRecordsToCSV(String filename) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
            for (List<String> record : records) {
                bw.write(record.get(0) + "," + record.get(1) + "," + record.get(2) + "," + record.get(3));
            }
        } catch (IOException e) {
            System.out.println("\nThe file for this username was not found\n");
        }
    }

    private static void passwordGenMenu() {
        while (true) {
            System.out.println("""
                    (1) Strong Password
                    (2) Custom Password
                    (3) Word Based Password
                    (4) Back
                    """);
            int choice = inputInt("Enter number: ", 1, 4);

            switch (choice) {
                case 1 -> {while (passwordMenu('s')) continue;}
                case 2 -> {while (passwordMenu('c')) continue;}
                case 3 -> {while (passwordMenu('w')) continue;}
                case 4 -> {return;}
            }
        }
    }

    private static void settingsMenu() {
        while (true) {
            System.out.println("""
                    (1) Change Username
                    (2) Change Password
                    (3) Delete Account
                    (4) Back
                    """);
            int choice = inputInt("Enter number: ", 1, 4);

            switch (choice) {
                case 1 -> {
                    String newUsername = input("New Username: ");
                    records.get(0).set(1, newUsername);
                    renameCSVfile(accountUsername + ".csv", newUsername + ".csv");
                }
                case 2 -> passwordChange();
                case 3 -> deleteAccount();
                case 4 -> {return;}
            }
        }
    }

    private static void renameCSVfile(String oldName, String newName) {
        File oldFile = new File(oldName);
        File newFile = new File(newName);

        if (oldFile.renameTo(newFile)) {
            System.out.println("File renamed successfully.");
        } else {
            System.out.println("Failed to rename the file. Make sure the file exists and is not open in another program.");
        }
    }

    private static void passwordChange() {
        // finish
    }
    
    private static void deleteAccount() {
        if (!inputBool("Are you sure, you want to delete your account? ")) {
            System.out.println("\nCancelled\n");
            return;
        }

        File file = new File(accountUsername + ".csv");
        if (file.delete()) {
            System.out.println("Account deleted successfully.");
        } else {
            System.out.println("Failed to delete the account. The CSV file might be open in another program.");
        }
        System.exit(0);
    }

    private static void logIn() {
        String username = input("Username: ");
        String inputPassword = input("Password: ");
        if (!loadRecords(username + ".csv")) return;


        String userSalt = getUserSalt();

        byte[] hashedPassword = hashPassword(inputPassword, userSalt);
        byte[] userPassword = base64StringToByteArray(getUserPassword());

        if (comparePasswordHashes(hashedPassword, userPassword)) {
            setAccount(username, inputPassword);
            accountMenu();
        }
        else printWrongDetails();
    }

    private static void signUp() {
        String username = input("Username: ");
        String password;
        System.out.println("""
                (1) Generate Password
                (2) Choose Password
                """);

        int choice = inputInt("Enter Number: ", 1, 2);

        if (choice == 1) {
            password = generateStrongPassword();
            System.out.println("\nPassword: " + password + "\n");
        }
        else {
            password = input("\nPassword: ");
        }

        String repeatedPassword = input("\nRepeat Password: ");

        if (!password.equals(repeatedPassword)) {
            System.out.println("The passwords do not match");
            return;
        }

        createCSV(username, password, generateSalt());

    }

    private static void createCSV(String username, String password, String salt) {
        try (FileWriter fileWriter = new FileWriter(username + ".csv");
             PrintWriter printWriter = new PrintWriter(fileWriter)) {

            // Write the headers to the CSV file
            printWriter.println("PasswordManager," + username + "," + password + "," + salt);

            System.out.println("CSV file created successfully.");
        } catch (IOException e) {
            System.out.println("An error occurred while creating the CSV file.");
            e.printStackTrace();
        }
    }

    private static void setAccount(String username, String password) {
        accountUsername = username;
        accountPassword = password;
        System.out.println("\nWelcome, " + username + "\n");
    }

    private static void printWrongDetails() {
        System.out.println("\nWrong details\n");
    }

    private static void copyToClipboard(String s) {
        StringSelection stringSelection = new StringSelection(s);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        System.out.println("Copied to clipboard\n");
    }

    private static String getUserSalt() {
        return records.get(0).get(3);
    }

    private static String getUserPassword() {
        return records.get(0).get(2);
    }

    private static boolean comparePasswordHashes(byte[] hash1, byte[] hash2) {
        return Arrays.equals(hash1, hash2);
    }

    private static String byteArrayToBase64String(byte[] bytePassword) {
        return Base64.getEncoder().encodeToString(bytePassword);
    }

    private static byte[] base64StringToByteArray(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    private static void printAboutPage() {
        System.out.print("\n");
        try (Scanner scanner = new Scanner(new File("about.txt"))) {
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }

        } catch (IOException e) {System.out.println("\nThe about file was not found");}
        System.out.print("\n");
    }

    private static byte[] hashPassword(String passwordString, String salt) {
        passwordString += salt;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(passwordString.getBytes(StandardCharsets.UTF_16));
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Error has occurred");
            return new byte[0];
        }
    }

    private static byte[] hashPassword(String passwordString) {
        try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(passwordString.getBytes(StandardCharsets.UTF_16));
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Error has occurred");
            return new byte[0];
        }
    }

    private static String byteToString(byte[] b) {
        return new String(b, 0, b.length, StandardCharsets.UTF_16);
    }

    private static String generateSalt() {
        char[] chars = (LOWERCASE + UPPERCASE + DIGITS + SPECIAL_CHARACTERS).toCharArray();
        int len = chars.length;
        StringBuilder salt = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            salt.append(chars[randomNum(0, len)]);
        }
        return salt.toString();
    }

    private static String input(String message) {
        System.out.print(message);
        return new Scanner(System.in).nextLine();
    }

    private static boolean inputBool(String message) {
        String answer = input(message);
        return answer.length() > 0 && answer.charAt(0) == 'y';
    }

    private static int inputInt(String message) {
        System.out.print(message);
        try {
            return new Scanner(System.in).nextInt();
        }
        catch (InputMismatchException e) {
            return -1;
        }
    }

    private static int inputInt(String message, int min, int max) {
        int choice = inputInt(message);

        while (choice < min || choice > max) {
            choice = inputInt(message);
        }
        return choice;
    }

    private static String passwordGenerator(int length, boolean special_character, boolean extra_characters, boolean digits, boolean uppercase, boolean lowercase, boolean must_include_special_character, boolean must_include_uppercase) {

        StringBuilder password = new StringBuilder();


        String options = "";
        if (special_character) options += SPECIAL_CHARACTERS;
        if (extra_characters) options += EXTRA_CHARACTERS;
        if (digits) options += DIGITS;
        if (lowercase) options += LOWERCASE;
        if (uppercase) options += UPPERCASE;
        char[] char_options = options.toCharArray();
        int len = char_options.length;

        for (int i = length; i > 0; i--) {
            password.append(char_options[randomNum(0, len)]);
        }

        if (must_include_uppercase && !containsUppercase(password.toString())) {
            password = new StringBuilder(password.substring(0, length - 2) + UPPERCASE.charAt(randomNum(0, UPPERCASE.length())));
        }
        if (must_include_special_character && !containsSpecial(password.toString())) {
            password = new StringBuilder(password.substring(0, length - 1) + SPECIAL_CHARACTERS.charAt(randomNum(0, SPECIAL_CHARACTERS.length())));
            // length--; was here
        }

        return password.toString();
    }

    private static boolean containsSpecial(String s) {
        for (char c : SPECIAL_CHARACTERS.toCharArray()) {
            if (s.contains("" + c)) return true;
        }
        return false;
    }

    private static boolean containsUppercase(String s) {
        for (char c : UPPERCASE.toCharArray()) {
            if (s.contains("" + c)) return true;
        }
        return false;
    }

    private static String booleanToYesOrNo(boolean b) {
        if (b) return "YES";
        return "NO";
    }

    private static String generateCustomPassword() {
        System.out.println("\nCustomise password options:\n");
        int passwordLength = 16;
        boolean lowercase = true;
        boolean uppercase = true;
        boolean digits = true;
        boolean special = true;
        boolean extra = false;
        boolean mustContainUppercase = false;
        boolean mustContainSpecial = false;

        while (true) {
            System.out.printf("""
                                        
                    Can Include:
                    (1) Password Length     %s
                    (2) Lowercase Letters   %s
                    (3) Uppercase Letters   %s
                    (4) Digits              %s
                    (5) Special Characters  %s
                    (6) Extra Characters    %s
                                        
                    Must Include:
                    (7) Uppercase           %s
                    (8) Special Characters  %s
                                        
                    (9) Back
                    (0) Generate
                    %n""", passwordLength, booleanToYesOrNo(lowercase), booleanToYesOrNo(uppercase), booleanToYesOrNo(digits), booleanToYesOrNo(special), booleanToYesOrNo(extra), booleanToYesOrNo(mustContainUppercase), booleanToYesOrNo(mustContainSpecial));

            int choice = inputInt("Enter number: ", 0, 9);

            switch (choice) {
                case 1 -> {passwordLength = inputInt("Password length (3-2048): ", 3, 2048);}
                case 2 -> {lowercase = !lowercase;}
                case 3 -> {
                    uppercase = !uppercase;
                    if (!uppercase) mustContainUppercase = false;
                }
                case 4 -> {digits = !digits;}
                case 5 -> {
                    special = !special;
                    if (!special) mustContainSpecial = false;
                }
                case 6 -> {extra = !extra;}
                case 7 -> {
                    mustContainUppercase = !mustContainUppercase;
                    if (mustContainUppercase) uppercase = true;
                }
                case 8 -> {
                    mustContainSpecial = !mustContainSpecial;
                    if (mustContainSpecial) special = true;
                }
                case 9 -> {return "";}
                case 0 -> {return passwordGenerator(passwordLength, special, extra, digits, uppercase, lowercase, mustContainUppercase, mustContainSpecial);}
            }
        }
    }

    private static String generateWordBasedPassword() {
        int minLength = inputInt("Choose minimum length (3-64): ", 3, 64);
        int dictLen = wordsDict.size() - 1;

        StringBuilder password = new StringBuilder();

        while (password.length() < minLength) {
            password.append(wordsDict.get(randomNum(0, dictLen)));
        }
        return password.toString() + randomNum(1000, 9999);
    }

    private static void loadDictionary() {
        wordsDict = new ArrayList<>();
        try {
            File myObj = new File("dictionary.txt");
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                wordsDict.add(data);
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    private static String generateStrongPassword() {
        return passwordGenerator(16, true, false, true, true, true, false, false);
    }

    private static boolean passwordMenu(char passwordType) {
        String password = "";
        switch (passwordType) {
            case 's' -> password = generateStrongPassword();
            case 'w' -> password = generateWordBasedPassword();
            case 'c' -> password = generateCustomPassword();
        }

        if (password.equals("")) {
            System.out.println("\nPassword generation canceled\n");
            return false;
        }

        System.out.println("\n" + password + "\n");

        while (true) {
            System.out.println("""
                    (1) Copy
                    (2) Save
                    (3) New password
                    (4) Back
                    """);

            int choice = inputInt("Enter number: ", 1, 4);

            switch (choice) {
                case 1 -> {
                    copyToClipboard(password);
                    return false;
                }
                case 2 -> {
                    newPasswordSave(password);
                }
                case 3 -> {return true;}
                case 4 -> {return false;}
            }
        }
    }

    private static void newPasswordSave(String password) {
        String service = input("Service website: ");
        String username = input("Service username: ");
        String salt = generateSalt();
        byte[] hashedPassword = hashPassword(password, salt);
        String base64StringPassword = byteArrayToBase64String(hashedPassword);

        List<String> newRecord = new ArrayList<>();
        newRecord.add(service);
        newRecord.add(username);
        newRecord.add(base64StringPassword);
        newRecord.add(salt);
        records.add(newRecord);
        CSVfileRequiresRewriting = true;
        // finish

        try (FileWriter fileWriter = new FileWriter(accountUsername + ".csv", true);
             PrintWriter printWriter = new PrintWriter(fileWriter)) {

            // Append the line to the file
            printWriter.println(service + "," + username + "," + password + "," + salt);

            System.out.println("\nPassword added\n");
        } catch (IOException e) {
            System.out.println("An error occurred while updating password.");
            e.printStackTrace();
        }
    }

    private static int randomNum(int lowerbound, int upperbound) {
        Random r = new Random();
        return lowerbound + r.nextInt(upperbound - lowerbound);
    }
}