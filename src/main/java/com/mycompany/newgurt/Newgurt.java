package com.mycompany.newgurt;

import javax.swing.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Newgurt {

    static class ChatMessage {
        String from, to, text, time, msgID, checksum;

        public ChatMessage(String from, String to, String text) {
            this.from = from;
            this.to = to;
            this.text = text;
            this.time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            this.msgID = "ID" + System.currentTimeMillis();
            this.checksum = createChecksum(text);
        }

        public String toJSON() {
            return String.format("{\"from\":\"%s\",\"to\":\"%s\",\"text\":\"%s\",\"time\":\"%s\",\"msgID\":\"%s\",\"checksum\":\"%s\"}",
                    from, to, text.replace("\"", "\\\""), time, msgID, checksum);
        }

        public static String createChecksum(String text) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(text.getBytes());
                StringBuilder hex = new StringBuilder();
                for (byte b : hash) hex.append(String.format("%02x", b));
                return hex.toString();
            } catch (NoSuchAlgorithmException e) {
                return "error";
            }
        }

        public String showDetails() {
            return String.format("Sender: %s\nReceiver: %s\nText: %s\nTime: %s\nID: %s\nChecksum: %s",
                    from, to, text, time, msgID, checksum);
        }
    }

    static HashMap<String, String[]> userDatabase = new HashMap<>();
    static ArrayList<ChatMessage> deliveredMsgs = new ArrayList<>();
    static ArrayList<ChatMessage> ignoredMsgs = new ArrayList<>();
    static ArrayList<ChatMessage> savedMsgs = new ArrayList<>();
    static ArrayList<String> checksums = new ArrayList<>();
    static ArrayList<String> msgIDs = new ArrayList<>();
    static String activeUser = null;

    public static boolean validUser(String user) {
        return user.length() <= 5 && user.contains("_");
    }

    public static boolean validPass(String pass) {
        return pass.matches(".*[!@#$%^&()].*");
    }

    public static boolean validPhone(String phone) {
        return phone.matches("\\+\\d{10,13}");
    }

    public static void saveToFile() {
        try (FileWriter fw = new FileWriter("messages.json")) {
            fw.write("[\n" + String.join(",\n", 
                deliveredMsgs.stream().map(ChatMessage::toJSON).toArray(String[]::new)) + "\n]");
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "Save error: " + e.getMessage());
        }
    }

    public static void loadFromFile() {
        try {
            String json = new String(Files.readAllBytes(Paths.get("messages.json")));
            if (!json.trim().startsWith("[")) return;
            Arrays.stream(json.split("\\},\\s*\\{"))
                .map(entry -> entry.replaceAll("[\\[\\]{}]", ""))
                .forEach(entry -> {
                    Map<String, String> fields = new HashMap<>();
                    Arrays.stream(entry.split(",\\s*"))
                        .forEach(field -> {
                            String[] parts = field.split(":", 2);
                            if (parts.length == 2) fields.put(parts[0].replaceAll("\"", ""), parts[1].replaceAll("\"", ""));
                        });
                    savedMsgs.add(new ChatMessage(
                        fields.get("from"), 
                        fields.get("to"), 
                        fields.get("text")
                    ));
                });
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "No saved messages.");
        }
    }

    public static void main(String[] args) {
        loadFromFile();

        String[] actions = {"Register", "Login", "Quit"};
        while (true) {
            int choice = JOptionPane.showOptionDialog(null, "✨ Messaging App ✨", "Auth",
                JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, actions, actions[0]);

            if (choice == 0) {
                String user = JOptionPane.showInputDialog("Username (≤5 chars + _):");
                String pass = JOptionPane.showInputDialog("Password (needs !@#$%^&*):");
                String phone = JOptionPane.showInputDialog("Phone (+27831234567):");
                if (!validUser(user)) JOptionPane.showMessageDialog(null, "Invalid username.");
                else if (!validPass(pass)) JOptionPane.showMessageDialog(null, "Invalid password.");
                else if (!validPhone(phone)) JOptionPane.showMessageDialog(null, "Invalid phone.");
                else {
                    userDatabase.put(user, new String[]{pass, phone});
                    JOptionPane.showMessageDialog(null, "Registered!");
                }
            } 
            else if (choice == 1) {
                String user = JOptionPane.showInputDialog("Username:");
                String pass = JOptionPane.showInputDialog("Password:");
                String phone = JOptionPane.showInputDialog("Phone:");
                if (userDatabase.containsKey(user)) {
                    String[] data = userDatabase.get(user);
                    if (data[0].equals(pass) && data[1].equals(phone)) {
                        activeUser = user;
                        break;
                    }
                }
                JOptionPane.showMessageDialog(null, "Login failed.");
            } 
            else System.exit(0);
        }

        String[] menu = {"Send", "Ignore", "Save", "Send Saved", "Longest", "Find by ID", "Find by Receiver", "Remove by Checksum", "View Report", "Exit"};
        while (true) {
            int action = JOptionPane.showOptionDialog(null, "Menu", "Options",
                JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, menu, menu[0]);

            if (action == 0) {
                String text = JOptionPane.showInputDialog("Message:");
                String to = JOptionPane.showInputDialog("To:");
                ChatMessage msg = new ChatMessage(activeUser, to, text);
                deliveredMsgs.add(msg);
                checksums.add(msg.checksum);
                msgIDs.add(msg.msgID);
                saveToFile();
                JOptionPane.showMessageDialog(null, "Sent!\n" + msg.showDetails());
            } 
            else if (action == 1) {
                String text = JOptionPane.showInputDialog("Message to ignore:");
                String to = JOptionPane.showInputDialog("To:");
                ignoredMsgs.add(new ChatMessage(activeUser, to, text));
                JOptionPane.showMessageDialog(null, "Ignored.");
            } 
            else if (action == 2) {
                String text = JOptionPane.showInputDialog("Message to save:");
                String to = JOptionPane.showInputDialog("To:");
                savedMsgs.add(new ChatMessage(activeUser, to, text));
                JOptionPane.showMessageDialog(null, "Saved.");
            } 
            else if (action == 3) {
                if (savedMsgs.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "No saved messages.");
                } else {
                    String[] options = savedMsgs.stream()
                        .map(m -> "To: " + m.to + " | " + m.text)
                        .toArray(String[]::new);
                    int selected = JOptionPane.showOptionDialog(null, "Send saved message:", "Saved",
                        JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);
                    if (selected >= 0) {
                        ChatMessage msg = savedMsgs.remove(selected);
                        deliveredMsgs.add(msg);
                        checksums.add(msg.checksum);
                        msgIDs.add(msg.msgID);
                        saveToFile();
                        JOptionPane.showMessageDialog(null, "Sent!\n" + msg.showDetails());
                    }
                }
            } 
            else if (action == 4) {
                String longest = deliveredMsgs.stream()
                    .max(Comparator.comparingInt(m -> m.text.length()))
                    .map(m -> m.text).orElse("No messages.");
                JOptionPane.showMessageDialog(null, "Longest: " + longest);
            } 
            else if (action == 5) {
                String id = JOptionPane.showInputDialog("Enter ID:");
                String result = deliveredMsgs.stream()
                    .filter(m -> m.msgID.equals(id))
                    .map(m -> "To: " + m.to + "\nMessage: " + m.text)
                    .findFirst().orElse("Not found");
                JOptionPane.showMessageDialog(null, result);
            } 
            else if (action == 6) {
                String receiver = JOptionPane.showInputDialog("Enter receiver:");
                StringBuilder output = new StringBuilder();
                for (ChatMessage m : deliveredMsgs) if (m.to.equals(receiver)) output.append(m.text).append("\n");
                for (ChatMessage m : savedMsgs) if (m.to.equals(receiver)) output.append(m.text).append("\n");
                JOptionPane.showMessageDialog(null, output.length() > 0 ? output.toString() : "None found");
            } 
            else if (action == 7) {
                String checksum = JOptionPane.showInputDialog("Enter checksum to delete:");
                boolean removed = deliveredMsgs.removeIf(m -> m.checksum.equals(checksum));
                JOptionPane.showMessageDialog(null, removed ? "Deleted." : "Not found.");
            } 
            else if (action == 8) {
                StringBuilder report = new StringBuilder("📜 Message Report:\n\n");
                for (ChatMessage m : deliveredMsgs) {
                    report.append("Checksum: ").append(m.checksum).append("\n");
                    report.append("To: ").append(m.to).append("\n");
                    report.append("Message: ").append(m.text).append("\n\n");
                }
                JOptionPane.showMessageDialog(null, report.toString());
            } 
            else System.exit(0);
        }
    }
}