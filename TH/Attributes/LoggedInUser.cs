namespace TH.Attributes
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
    public class LoggedInUser : Attribute
    {

    }
}
