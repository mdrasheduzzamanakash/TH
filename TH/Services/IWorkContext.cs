using System.Security.Claims;
using TH.Domains;

namespace TH.Services
{
    public interface IWorkContext
    {
        Customer GetCurrentCustomer();
        void SetCurrentCustomer(Customer customer);
        List<string> GetCurrentCustomerRoles();
        void SetCurrentCustomerRoles(List<string> claims);
    }
}
