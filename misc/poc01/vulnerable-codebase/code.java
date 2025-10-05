public class HelloWorld {
    private String password = "${db.password}";
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}