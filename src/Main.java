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

    // Master account credentials
    private static String masterUsername = null;
    private static String masterPassword = null;

    // Storage for all password records
    private static final List<List<String>> records = new ArrayList<>();

    // Flag to indicate whether the CSV file needs to be updated
    private static boolean CSVfileRequiresRewriting = false;

    // Constants for character sets used in password generation
    private static final String SPECIAL_CHARACTERS = "/?#@-=_+!^";
    private static final String EXTRA_CHARACTERS = "(){}[]|`¬~£$&*%<>.,:;\"'\\";
    private static final String LOWERCASE = "abcdefghigklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIGKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";

    // List to store a dictionary of words for word-based password generation
    private static List<String> wordsDict;

    // Clipboard to copy a password
    private static final Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();


    // Constants for encryption configuration
    private static final int SALT_LENGTH = 16;         // Salt length in bytes
    private static final int IV_LENGTH = 16;           // IV length in bytes for AES
    private static final int ITERATIONS = 65536;       // Number of PBKDF2 iterations
    private static final int KEY_LENGTH = 256;         // AES key length in bits


    /**
     * Starting point of the program
     *
     * @param args
     */
    public static void main(String[] args) {
        // load the words dictionary for generateWordBasedPassword() method:
        loadDictionary();

        // start the program:
        mainMenu();

    }

    /** //finish
     * Generate a random salt with size SALT_LENGTH
     *
     * @return generated salt as byte array
     */
    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Derive a key from the master password and salt that will be used for encryption
     *
     * @param salt will be added to masterPassword to derive a key
     * @return SecretKeySpec key
     * @throws Exception
     */
    private static SecretKeySpec deriveKey(byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(getMasterPassword().toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /** Generate a random Initialization Vector for AES
     * (random string of characters that will provide an initial state for encryption)
     *
     * @return Initialization Vector
     */
    private static byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Encrypt a text message using AES
     * The key will be derived from Master Password
     *
     *
     * @param plainText message to be encrypted
     * @return encrypted message
     * @throws Exception
     */
    public static String encrypt(String plainText) throws Exception {
        // Generate salt and derive key
        byte[] salt = generateSalt();
        SecretKeySpec key = deriveKey(salt);

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

    /**
     * Decrypt a text message using AES
     *
     * @param encryptedData
     * @return decrypted message
     * @throws Exception
     */
    public static String decrypt(String encryptedData) throws Exception {
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
        SecretKeySpec key = deriveKey(salt);

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Decrypt and return the plain text
        byte[] plainText = cipher.doFinal(encryptedText);
        return new String(plainText);
    }

    /**
     * Main menu with options for login, signup, and about page
     */
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
                case 1 -> logIn();
                case 2 -> signUp();
                case 3 -> printAboutPage();
                case 4 -> {return;}
            }
        }
    }

    /**
     * Password manager menu after logging-in
     * Allows to choose between 5 options
     */
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

    /**
     * Logs out the user, setting master username and password to null
     * Also empties the records arrayList
     * Runs writeRecordsToCSV() method if CSV file requires updating
     */
    private static void logOut() {
        if (doesCSVfileRequiresRewriting()) {
            writeRecordsToCSV(getMasterUsername() + ".csv");
        }
        setMasterUsername(null);
        setMasterPassword(null);
        initRecords(); // set records to new array
    }

    /**
     * Menu to manage all saved passwords
     * Allows to choose a saved password by entering its index in the list
     */
    private static void managePasswordsMenu() {
        while (true) {
            printAllAccounts();
            int choice = inputInt("Enter 0 to return or type password index to manage service: ");

            // Return if the user chooses 0 or an invalid index
            if (choice <= 0 || choice >= getRecordsSize()) return;

            // Allow user to manage a specific password
            menageServicePassword(choice);

        }
    }

    /**
     * Add a new password to the records
     */
    private static void addNewPassword() {
        String password = requestPasswordInput(); // Get password from user
        newPasswordSave(password); // Save it to the records
    }

    /**
     * Manage a specific service's password based on its index
     *
     * @param index index of the password in records arrayList
     */
    private static void menageServicePassword(int index) {
        // Display the service and username for the selected record
        System.out.println(getRecordsService(index));
        System.out.println(getRecordsUsername(index));
        try {
            // Attempt to decrypt and display the password
            System.out.println(decrypt(getRecordsPassword(index)));
        }
        catch (Exception e) {
            System.out.println("\n---Could not view password---\n");
        }

        System.out.println("""
                
                (1) Copy password
                (2) Change Password
                (3) Change Username
                (4) Remove Service
                (5) Back
                """);

        int choice = inputInt("Enter number: ", 1, 5);

        // Handle user's choice
        switch (choice) {
            case 1 -> {
                try {
                    // Copy the decrypted password to the clipboard
                    copyToClipboard(decrypt(getRecordsPassword(index)));
                }
                catch (Exception e) {
                    printErrorMessage();
                }
            }
            case 2 -> updatePassword(index); // Change the password
            case 3 -> setRecordsUsername(index, input("\nNew Username: ")); // Update the username
            case 4 -> removeService(index); // Remove the service from records
        }
    }

    /**
     * Remove a service record from the list if user confirms
     *
     * @param index index of the field to remove
     */
    private static void removeService(int index) {
        if (inputBool("Are you sure you want to delete this password: ")) removeRecord(index);
    }

    /**
     * Update the password for a specific record
     *
     * @param index index of the field to remove
     */
    private static void updatePassword(int index) {

        // Get a new password from user
        String newPasswordString = requestPasswordInput();
        String encryptedPassword;

        try {
            // encrypt the password
            encryptedPassword = encrypt(newPasswordString);
        }
        catch (Exception e) {
            printErrorMessage();
            return;
        }

        setRecordsPassword(index, encryptedPassword);
    }

    /**
     * Ask user to input or generate a password
     *
     * @return password
     */
    private static String requestPasswordInput() {
        System.out.println("""
                (1) Generate Strong Password
                (2) Enter Password
                """);
        int choice = inputInt("Enter number: ", 1, 2);

        if (choice == 1) {
            String password = generateStrongPassword();
            System.out.println("\n" + password + "\n");
            return password;
        }
        return input("\nNew Password: ");
    }

    /**
     * Print all account records for the user
     */
    private static void printAllAccounts() {
        System.out.print("\n");
        for (int i = 1; i < getRecordsSize(); i++) {
            System.out.println((i) + " " + getRecordsService(i) + " " + getRecordsUsername(i));
        }
        System.out.print("\n");
    }

    /**
     * Utility to copy text to clipboard
     *
     * @param filename name of the records CSV file
     * @return true if successful or false if not
     */
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

    /**
     * Writes data from records ArrayList into the CSV file
     *
     * @param filename name of the records CSV file
     */
    private static void writeRecordsToCSV(String filename) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
            for (List<String> record : getAllRecords()) {
                bw.write(record.get(0) + "," + record.get(1) + "," + record.get(2) + "," + record.get(3) + "\n");
            }
        } catch (IOException e) {
            System.out.println("\nThe file for this username was not found\n");
        }
    }

    /**
     * Menu for password generation options
     */
    private static void passwordGenMenu() {
        while (true) {
            System.out.println("""
                    (1) Strong Password
                    (2) Custom Password
                    (3) Word Based Password
                    (4) Back
                    """);

            // Get user choice with input validation
            int choice = inputInt("Enter number: ", 1, 4);

            switch (choice) {
                case 1 -> {while (passwordMenu('s')) continue;}
                case 2 -> {while (passwordMenu('c')) continue;}
                case 3 -> {while (passwordMenu('w')) continue;}
                case 4 -> {return;}
            }
        }
    }

    /**
     * Menu for account settings options
     */
    private static void settingsMenu() {
        while (true) {
            System.out.println("""
                    (1) Change Username
                    (2) Change Password
                    (3) Delete Account
                    (4) Back
                    """);

            // Get user choice with input validation
            int choice = inputInt("Enter number: ", 1, 4);

            switch (choice) {
                case 1 -> masterUsernameChange();
                case 2 -> masterPasswordChange();
                case 3 -> deleteAccount();
                case 4 -> {return;}
            }
        }
    }

    /**
     * Rename the CSV file when the master username is updated
     *
     * @param oldName current name of the file
     * @param newName new name for the file
     */
    private static void renameCSVfile(String oldName, String newName) {
        File oldFile = new File(oldName);
        File newFile = new File(newName);

        if (oldFile.renameTo(newFile)) {
            System.out.println("File renamed successfully.");
        } else {
            System.out.println("Failed to rename the file. Make sure the file exists and is not open in another program.");
        }
    }

    /**
     * Change the master username for the account
     */
    private static void masterUsernameChange() {
        String newUsername = input("New Username: ");
        setMasterUsername(newUsername);

        // Rename the associated CSV file
        renameCSVfile(getMasterUsername() + ".csv", newUsername + ".csv");
    }

    /**
     * Change the master password and update it in the records
     */
    private static void masterPasswordChange() {
        String newPassword = input("New Password: ");
        String salt = getRecordsMasterSalt();
        byte[] hashedPassword = hashPassword(newPassword, salt);
        String base64StringPassword = byteArrayToBase64String(hashedPassword);

        // finish

        setRecordsMasterPassword(base64StringPassword);
        System.out.println("\nPassword changed successfully\n");
    }

    /**
     * Delete the account by removing the associated CSV file
     */
    private static void deleteAccount() {
        // Confirm deletion with the user
        if (!inputBool("Are you sure, you want to delete your account? ")) {
            System.out.println("\nCancelled\n");
            return; // Exit if user cancels
        }

        // Attempt to delete the file
        File file = new File(getMasterUsername() + ".csv");
        if (file.delete()) {
            System.out.println("Account deleted successfully.");
        } else {
            System.out.println("Failed to delete the account. The CSV file might be open in another program.");
        }
        System.exit(0); // finish
    }


    /**
     * Log in to the account
     */
    private static void logIn() {
        String username = input("Username: ");
        String inputPassword = input("Password: ");

        // Load the user's records from the CSV file. if failed, return
        if (!loadRecords(username + ".csv")) return;

        // get salt
        String userSalt = getRecordsMasterSalt();

        // hash the password
        byte[] hashedPassword = hashPassword(inputPassword, userSalt);
        byte[] userPassword = base64StringToByteArray(getRecordsMasterPassword());

        // Compare the hashes to verify the password
        if (comparePasswordHashes(hashedPassword, userPassword)) {
            setAccount(username, inputPassword); // Set the details of the account
            accountMenu(); // Open the account menu
        }
        else System.out.println("\nWrong details\n");
    }

    /**
     * Sign up for a new account
     */
    private static void signUp() {
        String username = input("Username: ");
        String password;

        // Offer to generate or choose a password
        System.out.println("""
                (1) Generate Password
                (2) Choose Password
                """);

        int choice = inputInt("Enter Number: ", 1, 2);

        if (choice == 1) {
            password = generateStrongPassword(); // Generate a strong password
            System.out.println("\nPassword: " + password + "\n");
        }
        else {
            password = input("\nPassword: "); // Prompt for a custom password
        }

        // Confirm the password
        String repeatedPassword = input("\nRepeat Password: ");
        if (!password.equals(repeatedPassword)) {
            System.out.println("The passwords do not match");
            return; // Exit if passwords do not match
        }

        // Generate salt for the account and hash the password
        String salt = generateSaltString();
        byte[] hashedPassword = hashPassword(password, salt);
        String base64StringPassword = byteArrayToBase64String(hashedPassword);

        // Create the account CSV file
        createCSV(username, base64StringPassword, salt);
    }

    /**
     * Create a CSV file to store account data
     *
     * @param username master username, filename would be username.csv
     * @param password encrypted master password
     * @param salt salt for master password
     */
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

    /**
     * Set the account details in memory after login or signup
     *
     * @param username master username
     * @param password decrypted master password
     */
    private static void setAccount(String username, String password) {
        setMasterUsername(username);
        setMasterPassword(password);
        System.out.println("\nWelcome, " + username + "\n");
    }

    // Accessor Methods:

    // Master account details
    private static void setMasterUsername(String newUsername) {masterUsername = newUsername;}
    private static void setMasterPassword(String newPassword) {masterPassword = newPassword;}

    private static String getMasterUsername() {return masterUsername;}
    private static String getMasterPassword() {return masterPassword;}
    private static boolean doesCSVfileRequiresRewriting() {return CSVfileRequiresRewriting;}

    // Records ArrayList
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

    // Records Items
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

    /**
     * Copies a string into clipboard
     *
     * @param s string to copy
     */
    private static void copyToClipboard(String s) {
        StringSelection stringSelection = new StringSelection(s);
        clipboard.setContents(stringSelection, null);
        System.out.println("Copied to clipboard\n");
    }

    /**
     * Compares two password hashes to check if they are equal
     *
     * @param hash1 first hash value
     * @param hash2 second hash value
     * @return true if they are equal
     */
    private static boolean comparePasswordHashes(byte[] hash1, byte[] hash2) {
        return Arrays.equals(hash1, hash2);
    }

    /**
     * Converts a byte array into a Base64-encoded string
     *
     * @param bytePassword encrypted password as byte array
     * @return encrypted password as string
     */
    private static String byteArrayToBase64String(byte[] bytePassword) {
        return Base64.getEncoder().encodeToString(bytePassword);
    }

    /**
     * Converts a Base64-encoded string back to a byte array
     *
     * @param base64String encrypted password as string
     * @return encrypted password as byte array
     */
    private static byte[] base64StringToByteArray(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    /**
     * Prints the "About" page content from an external file
     */
    private static void printAboutPage() {
        System.out.print("\n");
        try (Scanner scanner = new Scanner(new File("about.txt"))) {
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine()); // Print each line from the file
            }

        } catch (IOException e) {System.out.println("\nThe about file was not found");}
        System.out.print("\n");
    }

    /**
     * Hashes a password combined with a salt using SHA-256
     *
     * @param passwordString unhashed string to be hashed
     * @param salt salt
     * @return hashed password as byte array
     */
    private static byte[] hashPassword(String passwordString, String salt) {
        passwordString += salt; // Combine the password with the salt
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Use SHA-256 for hashing
            return digest.digest(passwordString.getBytes(StandardCharsets.UTF_16)); // Hash the combined input
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Error has occurred");
            return new byte[0]; // Return empty array on error
        }
    }

    /**
     * Hashes a password without a salt
     *
     * @param passwordString unhashed string to be hashed
     * @return hashed password as byte array
     */
    private static byte[] hashPassword(String passwordString) {
        try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Use SHA-256 for hashing
        return digest.digest(passwordString.getBytes(StandardCharsets.UTF_16)); // Hash the combined input
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Error has occurred");
            return new byte[0]; // Return empty array on error
        }
    }

    /**
     * Converts a byte array to a string using UTF-16 encoding
     *
     * @param b byte array
     * @return resultant string
     */
    private static String byteToString(byte[] b) {
        return new String(b, 0, b.length, StandardCharsets.UTF_16);
    }

    /**
     * Generates a random string for hashing
     *
     * @return salt
     */
    private static String generateSaltString() {
        char[] chars = (LOWERCASE + UPPERCASE + DIGITS + SPECIAL_CHARACTERS).toCharArray();
        int len = chars.length;
        StringBuilder salt = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            salt.append(chars[randomNum(0, len)]);
        }
        return salt.toString();
    }

    /**
     * String input method
     * Displays a prompt message and returns user input as a string
     *
     * @param message to be printed
     * @return user input
     */
    private static String input(String message) {
        System.out.print(message);
        return new Scanner(System.in).nextLine();
    }

    /**
     * Boolean input method
     * Displays a prompt message and returns a boolean based on the user's response
     *
     * @param message to be printed
     * @return boolean user input
     */
    private static boolean inputBool(String message) {
        String answer = input(message);
        return answer.length() > 0 && answer.charAt(0) == 'y';
    }

    /**
     * Integer input method
     * Displays a prompt message and returns an integer input from the user
     *
     * @param message to be printed
     * @return Integer user input
     */
    private static int inputInt(String message) {
        System.out.print(message);
        try {
            return new Scanner(System.in).nextInt();
        }
        catch (InputMismatchException e) {
            return -1;
        }
    }

    /**
     * Integer input method with valid range
     * Displays a prompt and ensures the input is within a specified range
     *
     * @param message to be printed
     * @param min lowest allowed input value
     * @param max highest allowed input value
     * @return Integer user input
     */
    private static int inputInt(String message, int min, int max) {
        int choice = inputInt(message);

        while (choice < min || choice > max) { // Validate the input range
            choice = inputInt(message);
        }
        return choice;
    }

    /**
     * Generates a customizable password based on user-defined settings
     *
     * @param length length of the password
     * @param special_character include special characters
     * @param extra_characters include extra characters
     * @param digits include digits
     * @param uppercase include uppercase letters
     * @param lowercase include lowercase letters
     * @param must_include_special_character guarantees that a special character will be the password (only useful for short passwords)
     * @param must_include_uppercase guarantees that an uppercase letter will be the password (only useful for short passwords)
     * @return generated password
     */
    private static String passwordGenerator(int length, boolean special_character, boolean extra_characters, boolean digits, boolean uppercase, boolean lowercase, boolean must_include_special_character, boolean must_include_uppercase) {

        StringBuilder password = new StringBuilder();


        // Add allowed character sets to options
        String options = "";
        if (special_character) options += SPECIAL_CHARACTERS;
        if (extra_characters) options += EXTRA_CHARACTERS;
        if (digits) options += DIGITS;
        if (lowercase) options += LOWERCASE;
        if (uppercase) options += UPPERCASE;
        char[] char_options = options.toCharArray();
        int len = char_options.length;

        // Build the password by randomly picking characters
        for (int i = length; i > 0; i--) {
            password.append(char_options[randomNum(0, len)]);
        }

        // Ensure mandatory uppercase character inclusion
        if (must_include_uppercase && !containsUppercase(password.toString())) {
            password = new StringBuilder(password.substring(0, length - 2) + UPPERCASE.charAt(randomNum(0, UPPERCASE.length())));
        }
        // Ensure mandatory special character inclusion
        if (must_include_special_character && !containsSpecial(password.toString())) {
            password = new StringBuilder(password.substring(0, length - 1) + SPECIAL_CHARACTERS.charAt(randomNum(0, SPECIAL_CHARACTERS.length())));
            // length--; was here
        }

        return password.toString();
    }

    /**
     * Checks if a string contains at least one special character
     *
     * @param s string to be checked
     * @return true if contains special character
     */
    private static boolean containsSpecial(String s) {
        for (char c : SPECIAL_CHARACTERS.toCharArray()) {
            if (s.contains("" + c)) return true;
        }
        return false;
    }

    /**
     * Checks if a string contains at least one uppercase letter
     *
     * @param s string to be checked
     * @return true if contains uppercase letter
     */
    private static boolean containsUppercase(String s) {
        for (char c : UPPERCASE.toCharArray()) {
            if (s.contains("" + c)) return true;
        }
        return false;
    }

    /**
     * Converts a boolean value to "YES" or "NO" for display
     *
     * @param b boolean value
     * @return YES or NO
     */
    private static String booleanToYesOrNo(boolean b) {
        if (b) return "YES";
        return "NO";
    }

    /**
     * Generates a custom password based on user-defined settings
     * Asks user for password options and uses passwordGenerator() to get a password
     *
     * @return generated password
     */
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

        // Customization loop
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
                case 1 -> {
                    passwordLength = inputInt("Password length (3-2048): ", 3, 2048); // Set length
                }
                case 2 -> {
                    lowercase = !lowercase; // Toggle lowercase
                }
                case 3 -> {
                    uppercase = !uppercase; // Toggle uppercase
                    if (!uppercase) mustContainUppercase = false; // Ensure dependency
                }
                case 4 -> {
                    digits = !digits; // Toggle digits
                }
                case 5 -> {
                    special = !special; // Toggle special
                    if (!special) mustContainSpecial = false; // Ensure dependency
                }
                case 6 -> {
                    extra = !extra; // Toggle extra characters
                }
                case 7 -> {
                    mustContainUppercase = !mustContainUppercase;
                    if (mustContainUppercase) uppercase = true; // Ensure dependency
                }
                case 8 -> {
                    mustContainSpecial = !mustContainSpecial;
                    if (mustContainSpecial) special = true; // Ensure dependency
                }
                case 9 -> {return "";} // Cancels
                case 0 -> {return passwordGenerator(passwordLength, special, extra, digits, uppercase, lowercase, mustContainUppercase, mustContainSpecial);}
            }
        }
    }

    /**
     * Generates a word-based password using a dictionary of words
     *
     * @return generated password
     */
    private static String generateWordBasedPassword() {
        int minLength = inputInt("Choose minimum length (3-64): ", 3, 64);
        int dictLen = wordsDict.size() - 1;

        StringBuilder password = new StringBuilder();

        // Append random words until the password meets the required minimum length
        while (password.length() < minLength) {
            password.append(wordsDict.get(randomNum(0, dictLen))); // Randomly select words from the dictionary
        }
        // Append a random 4-digit number for additional uniqueness
        return password.toString() + randomNum(1000, 9999);
    }

    /**
     * Loads the dictionary file into a list for word-based password generation
     */
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

    /**
     * Generates a strong password using passwordGenerator() method with default secure arguments
     * (random string of 32 characters)
     *
     * @return generated password
     */
    private static String generateStrongPassword() {
        // Length 16, includes special characters, digits, uppercase, and lowercase, mustIncludeSpecial = false, mustIncludeUppercase = false
        return passwordGenerator(32, true, false, true, true, true, false, false);
    }

    /**
     * Handles the menu for password generation and user interaction
     * Method for password generation depends on passwordType:
     * s -> Strong Password
     * w -> Word Based Password
     * c -> Custom Password
     *
     * @param passwordType defines type of password to generate
     * @return true if new password generation is required
     */
    private static boolean passwordMenu(char passwordType) {
        String password = "";
        // Determine the password type to generate
        switch (passwordType) {
            case 's' -> password = generateStrongPassword();
            case 'w' -> password = generateWordBasedPassword();
            case 'c' -> password = generateCustomPassword();
        }

        // If password generation was canceled, inform the user
        if (password.equals("")) {
            System.out.println("\nPassword generation canceled\n");
            return false;
        }

        System.out.println("\n" + password + "\n");

        // Provide the user with options for the generated password
        System.out.println("""
                (1) Copy
                (2) Save
                (3) New password
                (4) Back
                """);

        int choice = inputInt("Enter number: ", 1, 4);

        // Handle user choice
        switch (choice) {
            case 1 -> copyToClipboard(password); // Copy the password to clipboard
            case 2 -> newPasswordSave(password); // Save the password to the records
            case 3 -> {return true;} // Generate a new password
        }
        // Return to the previous menu
        return false;
    }

    /**
     * Saves a newly generated password to the user's records
     *
     * @param unencryptedPassword password to be saved
     */
    private static void newPasswordSave(String unencryptedPassword) {
        String service = input("Service website: ");
        String username = input("Service username: ");
        byte[] salt = generateSalt(); // Generate unique salt for the record
        String encryptedPassword;

        try {
            encryptedPassword = encrypt(unencryptedPassword); // encrypt the password
        }
        catch (Exception e) {
            printErrorMessage();
            return;
        }

        // Create a new record with service, username, and encrypted password
        List<String> newRecord = new ArrayList<>();
        newRecord.add(service);
        newRecord.add(username);
        newRecord.add(encryptedPassword);
        newRecord.add(generateSaltString()); //finish

        addRecord(newRecord); // Append the record to all password records

        System.out.println("\nThe password has been saved\n");
    }

    /**
     * Displays "Something Went Wrong..." message
     */
    private static void printErrorMessage() {
        System.out.println("\nSomething went wrong...\n");
    }

    /**
     * Generates a random number between the specified minimum and maximum (inclusive)
     *
     * @param min the lowest number that could be generated
     * @param max the highest number that could be generated
     * @return a random number
     */
    private static int randomNum(int min, int max) {
        Random r = new Random();
        return min + r.nextInt(max - min);
    }
}