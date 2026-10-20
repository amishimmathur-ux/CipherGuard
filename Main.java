
import java.io.*;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

// Abstract class
abstract class SecurityTool {
    abstract void execute();
}

// Stores results without storing actual passwords
class AnalysisResult {
    private String time;
    private int score;
    private String strength;

    AnalysisResult(int score, String strength) {
        this.time = LocalDateTime.now().toString();
        this.score = score;
        this.strength = strength;
    }

    public String toString() {
        return time + " | Score: " + score + "/100 | " + strength;
    }
}

// Password checker inherits SecurityTool
class PasswordChecker extends SecurityTool {
    private static final String[] COMMON = {
        "password", "password123", "12345678",
        "qwerty123", "admin123", "iloveyou"
    };

    private String password;
    private Integer score;
    private String strength;
    private ArrayList<String> tips = new ArrayList<>();

    PasswordChecker(String password) {
        this.password = password;
    }

    // Overloaded method
    PasswordChecker(String password, int minimumLength) {
        this(password);
        if (password.length() < minimumLength)
            tips.add("Use at least " + minimumLength + " characters.");
    }

    boolean isCommon() {
        for (String common : COMMON) {
            if (password.equalsIgnoreCase(common))
                return true;
        }
        return false;
    }

    // Recursive demonstration
    int countDigits(int index) {
        if (index >= password.length()) return 0;
        int current = Character.isDigit(password.charAt(index)) ? 1 : 0;
        return current + countDigits(index + 1);
    }

    AnalysisResult analyze() {
        score = 0;
        tips.clear();

        boolean upper = false, lower = false;
        boolean digit = false, symbol = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) upper = true;
            else if (Character.isLowerCase(c)) lower = true;
            else if (Character.isDigit(c)) digit = true;
            else symbol = true;
        }

        if (password.length() >= 8) score += 25;
        else tips.add("Use at least 8 characters.");

        if (password.length() >= 12) score += 15;
        else tips.add("Consider using 12 or more characters.");

        if (upper) score += 15;
        else tips.add("Add an uppercase letter.");

        if (lower) score += 15;
        else tips.add("Add a lowercase letter.");

        if (digit) score += 15;
        else tips.add("Add a number.");

        if (symbol) score += 15;
        else tips.add("Add a special character.");

        if (isCommon()) {
            score = 0;
            tips.add("Avoid common passwords.");
        }

        // Wrapper class conversion
        int numericScore = score.intValue();

        if (isCommon()) strength = "Very Weak";
        else if (numericScore < 25) strength = "Very Weak";
        else if (numericScore < 50) strength = "Weak";
        else if (numericScore < 70) strength = "Medium";
        else if (numericScore < 90) strength = "Strong";
        else strength = "Very Strong";

        return new AnalysisResult(numericScore, strength);
    }

    void showResult() {
        AnalysisResult result = analyze();
        System.out.println("\nScore: " + score + "/100");
        System.out.println("Strength: " + strength);
        System.out.println("Common password: " + isCommon());
        System.out.println("Digits found: " + countDigits(0));

        if (tips.isEmpty()) {
            System.out.println("Great! All basic checks passed.");
        } else {
            System.out.println("Suggestions:");
            for (String tip : tips)
                System.out.println("- " + tip);
        }

        Main.history.add(result);
    }

    public void execute() {
        showResult();
    }

    String getStrength() {
        return strength;
    }
}

// Password generator also inherits SecurityTool
class PasswordGenerator extends SecurityTool {
    private final SecureRandom random = new SecureRandom();
    private final String characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*?";

    String generate(int length) {
        if (length < 8 || length > 64)
            throw new IllegalArgumentException(
                "Length must be between 8 and 64.");

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < length; i++) {
            result.append(characters.charAt(
                random.nextInt(characters.length())));
        }
        return result.toString();
    }

    public void execute() {
        Scanner input = Main.input;
        System.out.print("Password length (8-64): ");

        try {
            int length = input.nextInt();
            System.out.println("Generated password: " + generate(length));
            System.out.println("Keep it private and store it securely.");
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid length.");
        }
    }
}

// Synchronized history shared safely between threads
class PasswordHistory {
    private final ArrayList<AnalysisResult> records = new ArrayList<>();

    synchronized void add(AnalysisResult result) {
        records.add(result);
        notifyAll();
    }

    synchronized void display() {
        if (records.isEmpty()) {
            System.out.println("No analyses in this session.");
            return;
        }
        for (AnalysisResult result : records)
            System.out.println(result);
    }

    synchronized String report() {
        StringBuilder text = new StringBuilder("Password Analysis Report\n");
        for (AnalysisResult result : records)
            text.append(result).append("\n");
        return text.toString();
    }
}

// Background thread for saving reports
class ReportWorker extends Thread {
    private final PasswordHistory history;

    ReportWorker(PasswordHistory history) {
        this.history = history;
    }

    public void run() {
        try (PrintWriter writer = new PrintWriter(
                new FileWriter("password_report.txt"))) {
            writer.print(history.report());
            System.out.println("Report saved to password_report.txt");
        } catch (IOException e) {
            System.out.println("Unable to save report: " + e.getMessage());
        }
    }
}

public class Main {
    static final Scanner input = new Scanner(System.in);
    static final PasswordHistory history = new PasswordHistory();

    public static void main(String[] args) {
        int choice = 0;

        do {
            System.out.println("\n=== PASSWORD SECURITY TOOL ===");
            System.out.println("1. Check password strength");
            System.out.println("2. Generate password");
            System.out.println("3. View analysis history");
            System.out.println("4. Save report");
            System.out.println("5. Security tips");
            System.out.println("6. Exit");
            System.out.print("Choose: ");

            try {
                choice = Integer.parseInt(input.nextLine().trim());

                switch (choice) {
                    case 1:
                        System.out.print("Enter password to analyze: ");
                        String password = input.nextLine();
                        SecurityTool checker =
                            new PasswordChecker(password);
                        checker.execute();
                        break;

                    case 2:
                        SecurityTool generator = new PasswordGenerator();
                        generator.execute();
                        break;

                    case 3:
                        history.display();
                        break;

                    case 4:
                        new ReportWorker(history).start();
                        break;

                    case 5:
                        System.out.println("Use 12+ characters.");
                        System.out.println("Avoid names and common words.");
                        System.out.println("Never reuse important passwords.");
                        System.out.println("Use a password manager.");
                        break;

                    case 6:
                        System.out.println("Goodbye!");
                        break;

                    default:
                        System.out.println("Choose a number from 1 to 6.");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        } while (choice != 6);

        input.close();
    }
}