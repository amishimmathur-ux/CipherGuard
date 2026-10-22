
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

// Abstract class for all security tools.
abstract class SecurityTool {
    abstract void execute();
}

// Stores the result of a password analysis.
class AnalysisResult {
    private String time;
    private int score;
    private String strength;
    private String passwordHash;

    AnalysisResult(int score, String strength, String passwordHash) {
        this.time = LocalDateTime.now().toString();
        this.score = score;
        this.strength = strength;
        this.passwordHash = passwordHash;
    }

    String getPasswordHash() {
        return passwordHash;
    }

    public String toString() {
        return "Time: " + time + "\nScore: " + score + "/100" + "\nStrength: " + strength;
    }

    String getReportLine() {
        return toString() + "\nPassword hash: " + passwordHash;
    }
}

// Generates a salted password hash using PBKDF2.
class PasswordHasher {
    private SecureRandom random = new SecureRandom();

    String hashPassword(String password) throws Exception {
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        int iterations = 210000;
        char[] passwordChars = password.toCharArray();

        KeySpec spec = new PBEKeySpec(
                passwordChars, salt, iterations, 256);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            byte[] hash = factory.generateSecret(spec).getEncoded();

            return iterations + ":" + toHex(salt) + ":" + toHex(hash);
        } finally {
            Arrays.fill(passwordChars, '\0');
            ((PBEKeySpec) spec).clearPassword();
        }
    }

    private String toHex(byte[] data) {
        StringBuilder result = new StringBuilder();

        for (byte b : data) {
            result.append(String.format("%02x", b & 0xff));
        }

        return result.toString();
    }
}

// Checks password strength and gives improvement suggestions.
class PasswordChecker extends SecurityTool {
    private String password;
    private int score;
    private String strength;
    private ArrayList<String> suggestions;
    private PasswordHasher hasher;

    private String[] commonPasswords = {
        "password", "password123", "12345678", "qwerty123", "admin123", "iloveyou","123456", "123456789", "qwerty", "admin", "welcome123", "letmeinin"
    };

    PasswordChecker(String password) {
        this.password = password;
        suggestions = new ArrayList<>();
        hasher = new PasswordHasher();
    }

    // Constructor overloading.
    PasswordChecker(String password, int minimumLength) {
        this(password);

        if (password.length() < minimumLength) {
            suggestions.add( "Use at least " + minimumLength + " characters.");
        }
    }

    private boolean isCommonPassword() {
        for (String common : commonPasswords) {
            if (password.equalsIgnoreCase(common)) {
                return true;
            }
        }

        return false;
    }

    private boolean hasUppercase() {
        for (char ch : password.toCharArray()) {
            if (Character.isUpperCase(ch)) {
                return true;
            }
        }

        return false;
    }

    private boolean hasLowercase() {
        for (char ch : password.toCharArray()) {
            if (Character.isLowerCase(ch)) {
                return true;
            }
        }

        return false;
    }

    private boolean hasDigit() {
        for (char ch : password.toCharArray()) {
            if (Character.isDigit(ch)) {
                return true;
            }
        }

        return false;
    }

    private boolean hasSymbol() {
        for (char ch : password.toCharArray()) {
            if (!Character.isLetterOrDigit(ch)) {
                return true;
            }
        }

        return false;
    }

    // Recursive method to count digits in a password.
    private int countDigits(int position) {
        if (position >= password.length()) {
            return 0;
        }

        int current = Character.isDigit(password.charAt(position))
                ? 1 : 0;

        return current + countDigits(position + 1);
    }

    private void calculateStrength() {
        score = 0;
        suggestions.clear();

        if (password.length() >= 8) {
            score += 25;
        } else {
            suggestions.add("Use at least 8 characters.");
        }

        if (password.length() >= 12) {
            score += 15;
        } else {
            suggestions.add("Try using 12 or more characters.");
        }

        if (hasUppercase()) {
            score += 15;
        } else {
            suggestions.add("Add an uppercase letter.");
        }

        if (hasLowercase()) {
            score += 15;
        } else {
            suggestions.add("Add a lowercase letter.");
        }

        if (hasDigit()) {
            score += 15;
        } else {
            suggestions.add("Add a number.");
        }

        if (hasSymbol()) {
            score += 15;
        } else {
            suggestions.add("Add a special character.");
        }

        if (isCommonPassword()) {
            score = 0;
            suggestions.clear();
            suggestions.add("Avoid common passwords that are easy to guess.");
        }

        if (score >= 85) {
            strength = "Strong";
        } else if (score >= 60) {
            strength = "Moderate";
        } else {
            strength = "Weak";
        }
    }

    @Override
    void execute() {
        calculateStrength();

        try {
            String passwordHash = hasher.hashPassword(password);

            AnalysisResult result = new AnalysisResult(score, strength, passwordHash);

            System.out.println("\n----- PASSWORD ANALYSIS -----");
            System.out.println(result);
            System.out.println("Common password: " + (isCommonPassword() ? "Yes" : "No"));
            System.out.println("Number of digits: " + countDigits(0));

            if (!suggestions.isEmpty()) {
                System.out.println("\nSuggestions:");

                for (String suggestion : suggestions) {
                    System.out.println("- " + suggestion);
                }
            }

            Main.history.add(result);

            System.out.println("\nAnalysis saved in session history.");

        } catch (Exception e) {
            System.out.println("Could not create the password hash.");
        }
    }
}

// Generates random passwords.
class PasswordGenerator extends SecurityTool {
    private SecureRandom random = new SecureRandom();

    private String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789!@#$%^&*()-_+=";

    String generate(int length) {
        if (length < 8 || length > 64) {
            throw new IllegalArgumentException("Length must be between 8 and 64.");
        }

        StringBuilder password = new StringBuilder();

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            password.append(characters.charAt(index));
        }

        return password.toString();
    }

    @Override
    void execute() {
        try {
            System.out.print("Enter password length (8-64): ");

            int length = Integer.parseInt(Main.input.nextLine().trim());

            String generatedPassword = generate(length);

            System.out.println("\nGenerated password: " + generatedPassword);
            System.out.println("Keep it private and store it safely.");

        } catch (NumberFormatException e) {
            System.out.println("Please enter a valid number.");
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        }
    }
}

// Stores all password analysis results during the current session.
class PasswordHistory {
    private ArrayList<AnalysisResult> results = new ArrayList<>();

    synchronized void add(AnalysisResult result) {
        results.add(result);
        notifyAll();
    }

    synchronized void display() {
        if (results.isEmpty()) {
            System.out.println("No password checks yet.");
            return;
        }

        System.out.println("\nANALYSIS HISTORY");

        for (int i = 0; i < results.size(); i++) {
            System.out.println("\nAnalysis number: " + (i + 1));
            System.out.println(results.get(i));
        }
    }

    // Displays the hash for whichever analysis the user selects.
    synchronized void displayHash(int resultNumber) {
        if (resultNumber < 1 || resultNumber > results.size()) {
            System.out.println("Invalid analysis number.");
            return;
        }

        AnalysisResult result = results.get(resultNumber - 1);

        System.out.println("\nHash for analysis " + resultNumber + ":");
        System.out.println(result.getPasswordHash());
    }

    synchronized String createReport() {
        StringBuilder report = new StringBuilder();

        report.append("CIPHERGUARD PASSWORD REPORT\n");
        report.append("===========================\n\n");

        if (results.isEmpty()) {
            report.append("No password checks were recorded.\n");
        }

        for (int i = 0; i < results.size(); i++) {
            report.append("Analysis number: ").append(i + 1).append("\n");
            report.append(results.get(i).getReportLine());
            report.append("\n\n---------------------------\n\n");
        }

        return report.toString();
    }
}

// Saves the report using a separate thread.
class ReportWorker extends Thread {
    private PasswordHistory history;

    ReportWorker(PasswordHistory history) {
        this.history = history;
    }

    @Override
    public void run() {
        try (FileWriter writer = new FileWriter("password_report.txt")) {
            writer.write(history.createReport());
            System.out.println("Report saved to password_report.txt");
        } catch (IOException e) {
            System.out.println("Error saving the report: "+ e.getMessage());
        }
    }
}

// Main class containing the menu.
public class Main {
    static final Scanner input = new Scanner(System.in);
    static final PasswordHistory history = new PasswordHistory();
    public static void main(String[] args) {
        int choice = 0;
        System.out.println("==============================");
        System.out.println("       CIPHERGUARD TOOL");
        System.out.println("==============================");
        while (choice != 7) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Check password strength");
            System.out.println("2. Generate a password");
            System.out.println("3. View analysis history");
            System.out.println("4. Save report to a file");
            System.out.println("5. Show security tips");
            System.out.println("6. View hash of any previous analysis");
            System.out.println("7. Exit");
            System.out.print("Enter your choice: ");
            try {
                String menuInput = input.nextLine().trim();
                if (menuInput.isEmpty()) {
                    System.out.println("Please enter a menu number.");
                    continue;
                }
                choice = Integer.parseInt(menuInput);
                if (choice < 1 || choice > 7) {
                    System.out.println("Choose a number from 1 to 7.");
                    continue;
                }
                switch (choice) {
                    case 1:
                        System.out.print("Enter a password to check: ");
                        String password = input.nextLine();
                        if (password.isEmpty()) {
                            System.out.println("Password cannot be empty.");
                        } else {
                            SecurityTool checker =new PasswordChecker(password);
                            checker.execute();
                        }
                        break;
                    case 2:
                        SecurityTool generator =new PasswordGenerator();
                        generator.execute();
                        break;
                    case 3:
                        history.display();
                        break;
                    case 4:
                        ReportWorker worker =new ReportWorker(history);
                        worker.start();
                        try {
                            worker.join();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            System.out.println("Report saving was interrupted.");
                        }
                        break;
                    case 5:
                        showSecurityTips();
                        break;
                    case 6:
                        history.display();
                        System.out.print("\nEnter the analysis number whose hash you want: ");
                        try {
                            int resultNumber = Integer.parseInt(input.nextLine().trim());
                            history.displayHash(resultNumber);
                        } catch (NumberFormatException e) {
                            System.out.println("Please enter a valid number.");
                        }
                        break;
                    case 7:
                        System.out.println("Thank you!");
                        break;
                    default:
                        System.out.println("Invalid choice.");
                }
            } catch (NumberFormatException e) {
                System.out.println("Please enter a valid menu number.");
            }
        }
        input.close();
    }
    private static void showSecurityTips() {
        System.out.println("\n----- PASSWORD SECURITY TIPS -----");
        System.out.println("1. Use at least 12 characters.");
        System.out.println("2. Mix uppercase and lowercase letters.");
        System.out.println("3. Include numbers and special characters.");
        System.out.println("4. Avoid names, birthdays and common words.");
        System.out.println("5. Do not reuse passwords across websites.");
        System.out.println("6. Never share your password or its hash.");
        System.out.println("7. Use a trusted password manager.");
    }
}