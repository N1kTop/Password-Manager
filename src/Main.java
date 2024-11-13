import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.*;

public class Main {

    private static String masterUsername = null;
    private static String masterPassword = null;
    private static List<List<String>> records = new ArrayList<>();
    private static boolean CSVfileRequiresRewriting = false;
    private static final String SPECIAL_CHARACTERS = "/?#@-=_+!^";
    private static final String EXTRA_CHARACTERS = "(){}[]|`¬~£$&*%<>.,:;\"'\\";
    private static final String LOWERCASE = "abcdefghigklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIGKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";

    private static List<String> wordsDict;


    private static final int SALT_LENGTH = 16;         // Salt length in bytes
    private static final int IV_LENGTH = 16;           // IV length in bytes for AES
    private static final int ITERATIONS = 65536;       // Number of PBKDF2 iterations
    private static final int KEY_LENGTH = 256;         // AES key length in bits


    public static void main(String[] args) throws Exception {
        encryptionTest(args);

        loadDictionary();
        mainMenu();

    }

    // Generate a random salt
    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    // Derive a key from the master password and salt
    private static SecretKeySpec deriveKey(String masterPassword, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Generate a random IV for AES
    private static byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Encrypt text using the master password
    public static String encrypt(String masterPassword, String plainText) throws Exception {
        // Generate salt and derive key
        byte[] salt = generateSalt();
        SecretKeySpec key = deriveKey(masterPassword, salt);

        // Generate IV and initialize cipher for encryption
        byte[] iv = generateIv();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // Encrypt the text
        byte[] encryptedText = cipher.doFinal(plainText.getBytes());

        // Combine salt, IV, and encrypted text
        byte[] encryptedData = new byte[SALT_LENGTH + IV_LENGTH + encryptedText.length];
        System.arraycopy(salt, 0, encryptedData, 0, SALT_LENGTH);
        System.arraycopy(iv, 0, encryptedData, SALT_LENGTH, IV_LENGTH);
        System.arraycopy(encryptedText, 0, encryptedData, SALT_LENGTH + IV_LENGTH, encryptedText.length);

        // Encode and return the combined data
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Decrypt text using the master password
    public static String decrypt(String masterPassword, String encryptedData) throws Exception {
        // Decode the Base64-encoded data
        byte[] data = Base64.getDecoder().decode(encryptedData);

        // Extract salt, IV, and encrypted text
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] encryptedText = new byte[data.length - SALT_LENGTH - IV_LENGTH];

        System.arraycopy(data, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(data, SALT_LENGTH, iv, 0, IV_LENGTH);
        System.arraycopy(data, SALT_LENGTH + IV_LENGTH, encryptedText, 0, encryptedText.length);

        // Derive the key using the master password and salt
        SecretKeySpec key = deriveKey(masterPassword, salt);

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Decrypt and return the plain text
        byte[] plainText = cipher.doFinal(encryptedText);
        return new String(plainText);
    }

    public static void encryptionTest(String[] args) {
        try {
            setMasterPassword("password");
            String textToEncrypt = "Sensitive information";

            // Encrypt the text
            String encryptedData = encrypt(getMasterPassword(), textToEncrypt);
            System.out.println("Encrypted Data: " + encryptedData);

            // Decrypt the text
            String decryptedText = decrypt(getMasterPassword(), encryptedData);
            System.out.println("Decrypted Text: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
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
            writeRecordsToCSV(getMasterUsername() + ".csv");
        }
        setMasterUsername(null);
        setMasterPassword(null);
    }

    private static void managePasswordsMenu() {
        while (true) {
            printAllAccounts();
            int choice = inputInt("Enter 0 to return or type password index to manage service: ");

            if (choice <= 0 || choice >= getRecordsSize()) return;

            menageServicePassword(choice);

        }
    }

    private static void addNewPassword() {
        String password = requestPasswordInput();
        newPasswordSave(password);
    }

    private static void menageServicePassword(int index) {
        System.out.println(getRecordsService(index));
        System.out.println(getRecordsUsername(index));
        System.out.println(getRecordsPassword(index));

        System.out.println("""
                
                (1) Copy password
                (2) Change Password
                (3) Change Username
                (4) Remove Service
                (5) Back
                """);

        int choice = inputInt("Enter number: ", 1, 4);

        switch (choice) {
            case 1 -> {
                try {
                    copyToClipboard(decrypt(getMasterPassword(), getRecordsPassword(index)));
                }
                catch (Exception e) {
                    System.out.println("\nSomething went wrong...\n");
                }
            }
            case 2 -> updatePassword(index);
            case 3 -> setRecordsUsername(index, "\nNew Username: ");
            case 4 -> removeRecord(index);
        }
    }

    private static void updatePassword(int index) {

        String newPasswordString = requestPasswordInput();
        String encryptedPassword;

        try {
            encryptedPassword = encrypt(getMasterPassword(), newPasswordString);
        }
        catch (Exception e) {
            System.out.println("\nSomething went wrong...\n");
            return;
        }

        setRecordsPassword(index, encryptedPassword);
    }

    private static String requestPasswordInput() {
        System.out.println("""
                (1) Generate Strong Password
                (2) Enter Password
                """);
        int choice = inputInt("Enter number: ", 1, 2);

        if (choice == 1) return generateStrongPassword();
        return input("\nNew Password: ");
    }

    private static void printAllAccounts() {
        System.out.print("\n");
        for (int i = 1; i < getRecordsSize(); i++) {
            System.out.println((i) + " " + records.get(i).get(0) + " " + records.get(i).get(1));
        }
        System.out.print("\n");
    }

    private static boolean loadRecords(String filename) {
        initRecords();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                addRecord(Arrays.asList(values));
            }
            return true;
        } catch (IOException e) {
            System.out.println("\nThe file for this username was not found\n");
            return false;
        }
    }

    private static void writeRecordsToCSV(String filename) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
            for (List<String> record : getAllRecords()) {
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
                case 1 -> masterUsernameChange();
                case 2 -> masterPasswordChange();
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

    private static void masterUsernameChange() {
        String newUsername = input("New Username: ");
        setMasterUsername(newUsername);

        renameCSVfile(getMasterUsername() + ".csv", newUsername + ".csv");
    }

    private static void masterPasswordChange() {
        String newPassword = input("New Password: ");
        String salt = getRecordsMasterSalt();
        byte[] hashedPassword = hashPassword(newPassword, salt);
        String base64StringPassword = byteArrayToBase64String(hashedPassword);

        // finish // finish // finish

        setRecordsMasterPassword(base64StringPassword);
    }
    
    private static void deleteAccount() {
        if (!inputBool("Are you sure, you want to delete your account? ")) {
            System.out.println("\nCancelled\n");
            return;
        }

        File file = new File(getMasterUsername() + ".csv");
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


        String userSalt = getRecordsMasterSalt();

        byte[] hashedPassword = hashPassword(inputPassword, userSalt);
        byte[] userPassword = base64StringToByteArray(getRecordsMasterPassword());

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

        String salt = generateSaltString();
        byte[] hashedPassword = hashPassword(password, salt);
        String base64StringPassword = byteArrayToBase64String(hashedPassword);

        createCSV(username, base64StringPassword, salt);

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
        setMasterUsername(username);
        setMasterPassword(password);
        System.out.println("\nWelcome, " + username + "\n");
    }

    // Accessor Methods:
    private static void setMasterUsername(String newUsername) {masterUsername = newUsername;}
    private static void setMasterPassword(String newPassword) {masterPassword = newPassword;}
    private static String getMasterUsername() {return masterUsername;}
    private static String getMasterPassword() {return masterPassword;}
    private static boolean doesCSVfileRequiresRewriting() {return CSVfileRequiresRewriting;}


    private static List<List<String>> getAllRecords() {return records;}
    private static List<String> getRecord(int index) {return records.get(index);}
    private static int getRecordsSize() {return records.size();}
    private static void addRecord(List<String> newRecord) {
        records.add(newRecord);
        CSVfileRequiresRewriting = true;
    }
    private static void removeRecord(int index) {
        records.remove(index);
        CSVfileRequiresRewriting = true;
    }
    private static void initRecords() {new ArrayList<>();}

    private static String getRecordsService(int index) {return records.get(index).get(0);}
    private static String getRecordsUsername(int index) {return records.get(index).get(1);}
    private static String getRecordsPassword(int index) {return records.get(index).get(2);}
    private static String getRecordsSalt(int index) {return records.get(index).get(3);}

    private static void setRecordsUsername(int index, String newUsername) {
        records.get(index).set(1, newUsername);
        CSVfileRequiresRewriting = true;
    }
    private static void setRecordsPassword(int index, String newPassword) {
        records.get(index).set(2, newPassword);
        CSVfileRequiresRewriting = true;
    }
    private static void setRecordsSalt(int index, String newSalt) {
        records.get(index).set(3, newSalt);
        CSVfileRequiresRewriting = true;
    }

    private static void setRecordsMasterPassword(String newPassword) {
        records.get(0).set(2, newPassword);
        CSVfileRequiresRewriting = true;
    }
    private static void setRecordsMasterSalt(String newSalt) {
        records.get(0).set(3, newSalt);
        CSVfileRequiresRewriting = true;
    }

    private static String getRecordsMasterSalt() {return records.get(0).get(3);}
    private static String getRecordsMasterPassword() {return records.get(0).get(2);}

    private static void printWrongDetails() {
        System.out.println("\nWrong details\n");
    }

    private static void copyToClipboard(String s) {
        StringSelection stringSelection = new StringSelection(s);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        System.out.println("Copied to clipboard\n");
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

    private static String generateSaltString() {
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

    private static void newPasswordSave(String unencryptedPassword) {
        String service = input("Service website: ");
        String username = input("Service username: ");
        byte[] salt = generateSalt();
        String encryptedPassword;

        try {
            encryptedPassword = encrypt(getMasterPassword(), unencryptedPassword);
        }
        catch (Exception e) {
            System.out.println("\nSomething went wrong...\n");
            return;
        }

        List<String> newRecord = new ArrayList<>();
        newRecord.add(service);
        newRecord.add(username);
        newRecord.add(encryptedPassword);
        newRecord.add("salt");

        addRecord(newRecord);
    }

    private static int randomNum(int lowerbound, int upperbound) {
        Random r = new Random();
        return lowerbound + r.nextInt(upperbound - lowerbound);
    }
}