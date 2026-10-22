
import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

// Common parent for the security tools
abstract class SecurityTool {
    abstract void execute();
}

// Stores the result of one password check
class AnalysisResult {
    private final String time;
    private final int score;
    private final String strength;
    private final String passwordHash;

    AnalysisResult(int score, String strength, String passwordHash) {
        this.time = new Date().toString();
        this.score = score;
        this.strength = strength;
        this.passwordHash = passwordHash;
    }

    // Used for normal console history
    public String toString() {
        return time + " | Score: " + score + "/100 | " + strength;
    }

    // Used only when creating the report
    String getReportLine() {
        return toString() + "\nPassword hash: " + passwordHash + "\n";
    }
}

// Creates a salted password hash
class PasswordHasher {
    private static final int ITERATIONS = 210000;
    private final SecureRandom random = new SecureRandom();

    String hashPassword(String password) {
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] hash = createHash(password.toCharArray(), salt);

        return ITERATIONS + ":" + toHex(salt) + ":" + toHex(hash);
    }

    private byte[] createHash(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(
                password, salt, ITERATIONS, 256);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not hash password.", e);
        } finally {
            spec.clearPassword();
            Arrays.fill(password, '\0');
        }
    }

    private String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {
            result.append(String.format("%02x", b & 0xff));
        }

        return result.toString();
    }
}

// Checks password strength and gives suggestions
class PasswordChecker extends SecurityTool {
    private static final String[] COMMON_PASSWORDS = {
        "password", "password123", "12345678",
        "qwerty123", "admin123", "iloveyou"
    };

    private final String password;
    private final PasswordHasher hasher = new PasswordHasher();
    private final ArrayList<String> suggestions = new ArrayList<>();

    private int score;
    private String strength;

    PasswordChecker(String password) {
        this.password = password;
    }

    // Overloaded constructor
    PasswordChecker(String password, int minimumLength) {
        this(password);

        if (password.length() < minimumLength) {
            suggestions.add("Use at least " + minimumLength + " characters.");
        }
    }

    private boolean isCommonPassword() {
        for (String common : COMMON_PASSWORDS) {
            if (password.equalsIgnoreCase(common)) {
                return true;
            }
        }
        return false;
    }

    // Recursive method to count digits
    private int countDigits(int position) {
        if (position >= password.length()) {
            return 0;
        }

        int current = Character.isDigit(password.charAt(position)) ? 1 : 0;
        return current + countDigits(position + 1);
    }

    private void calculateStrength() {
        score = 0;
        suggestions.clear();

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSymbol = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else {
                hasSymbol = true;
            }
        }

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

        if (hasUpper) score += 15;
        else suggestions.add("Add an uppercase letter.");

        if (hasLower) score += 15;
        else suggestions.add("Add a lowercase letter.");

        if (hasDigit) score += 15;
        else suggestions.add("Add a number.");

        if (hasSymbol) score += 15;
        else suggestions.add("Add a special character.");

        if (isCommonPassword()) {
            score = 0;
            suggestions.add("Avoid common passwords.");
        }

        if (isCommonPassword() || score < 25) {
            strength = "Very Weak";
        } else if (score < 50) {
            strength = "Weak";
        } else if (score < 70) {
            strength = "Medium";
        } else if (score < 90) {
            strength = "Strong";
        } else {
            strength = "Very Strong";
        }
    }

    public void execute() {
        calculateStrength();

        // The hash is stored in the result, not printed
        String hash = hasher.hashPassword(password);
        AnalysisResult result = new AnalysisResult(score, strength, hash);

        System.out.println("\nPassword Analysis");
        System.out.println("Score: " + score + "/100");
        System.out.println("Strength: " + strength);
        System.out.println("Common password: " + isCommonPassword());
        System.out.println("Digits found: " + countDigits(0));

        if (suggestions.isEmpty()) {
            System.out.println("All basic checks passed.");
        } else {
            System.out.println("Suggestions:");
            for (String suggestion : suggestions) {
                System.out.println("- " + suggestion);
            }
        }

        Main.history.add(result);
        System.out.println("Analysis saved in session history.");
    }
}

// Generates random passwords
class PasswordGenerator extends SecurityTool {
    private final SecureRandom random = new SecureRandom();
    private final String characters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            + "0123456789!@#$%&*?";

    private String generate(int length) {
        if (length < 8 || length > 64) {
            throw new IllegalArgumentException(
                    "Length must be between 8 and 64.");
        }

        StringBuilder password = new StringBuilder();

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            password.append(characters.charAt(index));
        }

        return password.toString();
    }

    public void execute() {
        System.out.print("Enter password length (8-64): ");

        try {
            int length = Integer.parseInt(Main.input.nextLine().trim());
            System.out.println("Generated password: " + generate(length));
            System.out.println("Store it somewhere safe.");
        } catch (IllegalArgumentException e) {
            System.out.println("Please enter a valid length from 8 to 64.");
        }
    }
}

// Keeps a history of password checks
class PasswordHistory {
    private final ArrayList<AnalysisResult> records = new ArrayList<>();

    synchronized void add(AnalysisResult result) {
        records.add(result);
        notifyAll();
    }

    synchronized void display() {
        if (records.isEmpty()) {
            System.out.println("No analyses have been done yet.");
            return;
        }

        for (AnalysisResult result : records) {
            System.out.println(result);
        }
    }

    synchronized String createReport() {
        StringBuilder report = new StringBuilder();
        report.append("CipherGuard Password Analysis Report\n");
        report.append("====================================\n\n");

        for (AnalysisResult result : records) {
            report.append(result.getReportLine()).append("\n");
        }

        return report.toString();
    }
}

// Saves the report in a separate thread
class ReportWorker extends Thread {
    private final PasswordHistory history;

    ReportWorker(PasswordHistory history) {
        this.history = history;
    }

    public void run() {
        try (PrintWriter writer = new PrintWriter(
                new FileWriter("password_report.txt"))) {
            writer.print(history.createReport());
            System.out.println("Report saved to password_report.txt.");
        } catch (IOException e) {
            System.out.println("Could not save report: " + e.getMessage());
        }
    }
}

// Main program
public class Main {
    static final Scanner input = new Scanner(System.in);
    static final PasswordHistory history = new PasswordHistory();

    public static void main(String[] args) {
        int choice = 0;

        do {
            System.out.println("\n=== CIPHERGUARD ===");
            System.out.println("1. Check password strength");
            System.out.println("2. Generate password");
            System.out.println("3. View analysis history");
            System.out.println("4. Save report with password hashes");
            System.out.println("5. Security tips");
            System.out.println("6. Exit");
            System.out.print("Choose: ");

            String entry = input.nextLine().trim();

            if (entry.isEmpty()) {
                System.out.println("Please enter a menu number.");
                continue;
            }

            try {
                choice = Integer.parseInt(entry);
            } catch (NumberFormatException e) {
                System.out.println("Enter a number from 1 to 6.");
                continue;
            }

            switch (choice) {
                case 1:
                    System.out.print("Enter password to analyze: ");
                    new PasswordChecker(input.nextLine()).execute();
                    break;

                case 2:
                    new PasswordGenerator().execute();
                    break;

                case 3:
                    history.display();
                    break;

                case 4:
                    ReportWorker worker = new ReportWorker(history);
                    worker.start();
                    try {
                        worker.join();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        System.out.println("Report saving interrupted.");
                    }
                    break;

                case 5:
                    System.out.println("Use long, unique passwords.");
                    System.out.println("Avoid common words and reused passwords.");
                    System.out.println("Use a password manager and MFA.");
                    break;

                case 6:
                    System.out.println("Goodbye!");
                    break;

                default:
                    System.out.println("Choose a number from 1 to 6.");
            }
        } while (choice != 6);

        input.close();
    }
}
